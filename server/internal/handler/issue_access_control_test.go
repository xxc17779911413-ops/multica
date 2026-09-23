package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

func TestApplyIssueAccessControlIsAtomicVersionedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Atomic task ACL", "atomic-task-acl")
	fx := testutil.New(testPool, ws, testUserID)
	member := dbfx.User(t, "ACL member", "acl-member@example.test")
	fx.Member(t, ws, member, "member")
	project := fx.Project(t, "ACL project")
	issue := fx.Issue(t, "ACL task", testutil.Cols{"project_id": project})
	actor := projectauth.Subject{UserID: testUserID, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceOwner}
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	request := issueAccessControlRequest{ExpectedVersion: 1, ProjectAccessMode: projectauth.ProjectAccessRestricted,
		Grants: []issueAccessControlGrant{{SubjectType: projectauth.SubjectUser, SubjectID: member, Role: projectauth.RoleKey(projectauth.TaskMember), Scope: projectauth.RoleScopeTask, ExpiresAt: &expires}}}

	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state, changed, err := testHandler.applyIssueAccessControl(ctx, tx, actor, issue, project, request)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if !changed || state.PolicyVersion != 2 || state.ProjectAccessMode != projectauth.ProjectAccessRestricted {
		t.Fatalf("unexpected state: %#v", state)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var grants, audits, notifications int
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants WHERE workspace_id=$1 AND issue_id=$2 AND source='manual'`, ws, issue).Scan(&grants)
	fx.QueryRow(t, `SELECT count(*) FROM activity_log WHERE workspace_id=$1 AND issue_id=$2 AND action='task_access_control_updated'`, ws, issue).Scan(&audits)
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_granted'`, ws, issue, member).Scan(&notifications)
	if grants != 1 || audits != 1 {
		t.Fatalf("grants=%d audits=%d, want 1/1", grants, audits)
	}
	if notifications != 1 {
		t.Fatalf("notification count=%d, want 1", notifications)
	}
	var title, body string
	fx.QueryRow(t, `SELECT title,body FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_granted'`, ws, issue, member).Scan(&title, &body)
	if title != "ACL task" || !strings.Contains(body, "授予你「可编辑」权限") {
		t.Fatalf("unexpected notification title=%q body=%q", title, body)
	}

	// A transport retry with the same desired state is a no-op even though its
	// expected version is stale; it neither duplicates the row nor the audit.
	tx, _ = testPool.Begin(ctx)
	state, changed, err = testHandler.applyIssueAccessControl(ctx, tx, actor, issue, project, request)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if changed || state.PolicyVersion != 2 {
		t.Fatalf("idempotent retry changed state: %#v", state)
	}
	_ = tx.Rollback(ctx)
	fx.QueryRow(t, `SELECT count(*) FROM activity_log WHERE workspace_id=$1 AND issue_id=$2 AND action='task_access_control_updated'`, ws, issue).Scan(&audits)
	if audits != 1 {
		t.Fatalf("audit count=%d, want 1", audits)
	}
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_granted'`, ws, issue, member).Scan(&notifications)
	if notifications != 1 {
		t.Fatalf("notification count after retry=%d, want 1", notifications)
	}

	// A stale request for a different state gets a version conflict.
	request.ProjectAccessMode = projectauth.ProjectAccessInherit
	tx, _ = testPool.Begin(ctx)
	_, _, err = testHandler.applyIssueAccessControl(ctx, tx, actor, issue, project, request)
	_ = tx.Rollback(ctx)
	var conflict issuePolicyVersionConflict
	if !errors.As(err, &conflict) || conflict.current != 2 {
		t.Fatalf("error=%v, want version conflict at 2", err)
	}

	// Validation happens before destructive replacement; an invalid subject
	// leaves both the policy and the existing ACL intact.
	request.ExpectedVersion = 2
	request.Grants[0].SubjectID = "not-a-uuid"
	tx, _ = testPool.Begin(ctx)
	_, _, err = testHandler.applyIssueAccessControl(ctx, tx, actor, issue, project, request)
	_ = tx.Rollback(ctx)
	if !errors.Is(err, projectauth.ErrInvalidSubject) {
		t.Fatalf("error=%v, want invalid subject", err)
	}
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants WHERE workspace_id=$1 AND issue_id=$2 AND source='manual'`, ws, issue).Scan(&grants)
	if grants != 1 {
		t.Fatalf("grant count after rejected update=%d, want 1", grants)
	}
}

func TestApplyIssueAccessControlNotifiesOrganizationAndEveryoneRecipientsOnce(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Group task ACL notifications", "group-task-acl-notifications")
	fx := testutil.New(testPool, ws, testUserID)
	departmentMember := dbfx.User(t, "Department recipient", "department-recipient@example.test")
	everyoneMember := dbfx.User(t, "Everyone recipient", "everyone-recipient@example.test")
	fx.Member(t, ws, departmentMember, "member")
	fx.Member(t, ws, everyoneMember, "member")
	project := fx.Project(t, "Notification project")
	issue := fx.Issue(t, "Notification task", testutil.Cols{"project_id": project})
	rootOrganization := fx.Insert(t, "projectauth_organizations", testutil.Cols{
		"workspace_id": ws,
		"provider":     "test",
		"external_id":  "notification-department",
		"name":         "研发部",
	})
	childOrganization := fx.Insert(t, "projectauth_organizations", testutil.Cols{
		"workspace_id": ws,
		"provider":     "test",
		"external_id":  "notification-department-child",
		"name":         "研发一组",
		"parent_id":    rootOrganization,
	})
	fx.InsertNoID(t, "projectauth_organization_members", testutil.Cols{
		"workspace_id":    ws,
		"organization_id": childOrganization,
		"user_id":         departmentMember,
	}, "workspace_id=$1 AND organization_id=$2 AND user_id=$3", ws, childOrganization, departmentMember)

	actor := projectauth.Subject{UserID: testUserID, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceOwner}
	request := issueAccessControlRequest{
		ExpectedVersion:   1,
		ProjectAccessMode: projectauth.ProjectAccessInherit,
		Grants: []issueAccessControlGrant{
			{SubjectType: projectauth.SubjectOrganization, SubjectID: rootOrganization, Role: projectauth.RoleKey(projectauth.TaskMember), Scope: projectauth.RoleScopeTask},
			{SubjectType: projectauth.SubjectEveryone, Role: projectauth.RoleKey(projectauth.TaskViewer), Scope: projectauth.RoleScopeTask},
		},
	}
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := testHandler.applyIssueAccessControl(ctx, tx, actor, issue, project, request); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var departmentBody, everyoneBody string
	fx.QueryRow(t, `SELECT body FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_granted'`, ws, issue, departmentMember).Scan(&departmentBody)
	fx.QueryRow(t, `SELECT body FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_granted'`, ws, issue, everyoneMember).Scan(&everyoneBody)
	if !strings.Contains(departmentBody, "通过部门「研发部」授予你「可编辑」权限") {
		t.Fatalf("unexpected department notification: %q", departmentBody)
	}
	if !strings.Contains(everyoneBody, "通过「全员」授予你「可查看」权限") {
		t.Fatalf("unexpected everyone notification: %q", everyoneBody)
	}

	var total, actorNotifications int
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND type='task_access_granted'`, ws, issue).Scan(&total)
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_granted'`, ws, issue, testUserID).Scan(&actorNotifications)
	if total != 2 || actorNotifications != 0 {
		t.Fatalf("notifications total=%d actor=%d, want 2/0", total, actorNotifications)
	}
}

func TestIssueAccessControlRejectsWrongScopeAndExpiredGrant(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Scoped task ACL", "scoped-task-acl")
	fx := testutil.New(testPool, ws, testUserID)
	member := dbfx.User(t, "Scoped member", "scoped-member@example.test")
	fx.Member(t, ws, member, "member")

	for name, grant := range map[string]issueAccessControlGrant{
		"project role scope": {SubjectType: projectauth.SubjectUser, SubjectID: member, Role: "member", Scope: projectauth.RoleScopeProject},
		"expired":            {SubjectType: projectauth.SubjectUser, SubjectID: member, Role: "member", Scope: projectauth.RoleScopeTask, ExpiresAt: ptrTime(time.Now().Add(-time.Minute))},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := validateIssueAccessControlGrants(ctx, testPool, ws, []issueAccessControlGrant{grant})
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

// 2026-09-20 coder(lq): 前端只对「可管理」用户展示授权/审批入口，服务端必须
// 独立校验同一条件。读取、预览、写入三个入口加申请列表都要 403；只有
// “仅看自己的申请”（mine=true）对普通成员开放，受限页依赖它展示自己的状态。
func TestIssueAccessControlEndpointsRequireManage(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ws := dbfx.Workspace(t, "Task ACL gates", "task-acl-gates")
	fx := testutil.New(testPool, ws, testUserID)
	// The workspace owner stays ungranted on purpose: the bypass is off, so the
	// owner must not be able to manage this task either.
	fx.Member(t, ws, testUserID, "owner")
	viewer := dbfx.User(t, "Gate viewer", "gate-viewer@example.test")
	editor := dbfx.User(t, "Gate editor", "gate-editor@example.test")
	manager := dbfx.User(t, "Gate manager", "gate-manager@example.test")
	requester := dbfx.User(t, "Gate requester", "gate-requester@example.test")
	for _, user := range []string{viewer, editor, manager, requester} {
		fx.Member(t, ws, user, "member")
	}
	project := fx.Project(t, "Gate project")
	// The requester, not the workspace owner, creates the task: otherwise the
	// creator source would hand the ungranted owner IssueManage and the 403
	// assertion below would test the wrong thing.
	issue := fx.Issue(t, "Gated task", testutil.Cols{"project_id": project, "creator_id": requester})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)
	for user, role := range map[string]string{viewer: "viewer", editor: "member", manager: "manager"} {
		fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": user, "role_key": role, "source": "manual"})
	}

	// A complete replacement payload, so the 403 can only come from the gate and
	// never from request validation.
	payload := map[string]any{"expected_version": 1, "project_access_mode": "restricted", "grants": []any{}}
	endpoints := []struct {
		name   string
		method string
		path   string
		body   any
		call   func(http.ResponseWriter, *http.Request)
	}{
		{"read task access control", http.MethodGet, "access-control", nil, testHandler.GetIssueAccessControl},
		{"preview task access control", http.MethodPost, "access-control/preview", payload, testHandler.PreviewIssueAccessControl},
		{"list task access requests", http.MethodGet, "access-requests", nil, testHandler.ListIssueAccessRequests},
	}
	for _, endpoint := range endpoints {
		for _, user := range []string{viewer, editor, testUserID} {
			w := callIssueAccessEndpoint(endpoint.call, issueAccessHTTPRequest(user, ws, endpoint.method, issue, "", endpoint.body))
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s as %s: status=%d body=%s, want 403", endpoint.name, user, w.Code, w.Body.String())
			}
		}
		w := callIssueAccessEndpoint(endpoint.call, issueAccessHTTPRequest(manager, ws, endpoint.method, issue, "", endpoint.body))
		if w.Code != http.StatusOK {
			t.Fatalf("%s as manager: status=%d body=%s, want 200", endpoint.name, w.Code, w.Body.String())
		}
	}

	// The writable entry point obeys the same gate.
	for _, user := range []string{viewer, editor, testUserID} {
		w := callIssueAccessEndpoint(testHandler.PatchIssueAccessControl, issueAccessHTTPRequest(user, ws, http.MethodPatch, issue, "", payload))
		if w.Code != http.StatusForbidden {
			t.Fatalf("patch task access control as %s: status=%d body=%s, want 403", user, w.Code, w.Body.String())
		}
	}
	// The payload keeps the manager's own grant, so one actor can keep managing
	// the task after the replacement lands.
	payload["grants"] = []any{map[string]any{"subject_type": "user", "subject_id": manager, "role": "manager", "scope": "task"}, map[string]any{"subject_type": "user", "subject_id": requester, "role": "viewer", "scope": "task"}}
	w := callIssueAccessEndpoint(testHandler.PatchIssueAccessControl, issueAccessHTTPRequest(manager, ws, http.MethodPatch, issue, "", payload))
	if w.Code != http.StatusOK {
		t.Fatalf("patch task access control as manager: status=%d body=%s, want 200", w.Code, w.Body.String())
	}

	// The requester-facing exception: a plain member may always read their own
	// requests, which is what the restricted screen renders.
	mine := callIssueAccessEndpoint(testHandler.ListIssueAccessRequests, issueAccessHTTPRequest(viewer, ws, http.MethodGet, issue, "mine=true", nil))
	if mine.Code != http.StatusOK {
		t.Fatalf("own requests as viewer: status=%d body=%s, want 200", mine.Code, mine.Body.String())
	}
}

// A mention stores a real task grant outside the manual ACL. The access read must
// report it, because counting only manual rows told a manager "0 granted" while
// the mentioned teammate could plainly open the task.
func TestIssueAccessControlReportsDerivedGrantsReadOnly(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	ws := dbfx.Workspace(t, "Derived task access", "derived-task-access")
	fx := testutil.New(testPool, ws, testUserID)
	reader := dbfx.User(t, "Derived reader", "derived-reader@example.test")
	mentioned := dbfx.User(t, "Derived mentioned", "derived-mentioned@example.test")
	creator := dbfx.User(t, "Derived creator", "derived-creator@example.test")
	for _, user := range []string{reader, mentioned, creator} {
		fx.Member(t, ws, user, "member")
	}
	project := fx.Project(t, "Derived project")
	// A neutral creator, so a creator source cannot stand in for what is asserted.
	issue := fx.Issue(t, "Derived grant task", testutil.Cols{"project_id": project, "creator_id": creator})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)
	// The caller manages through a manual grant; the mention is what must show up
	// as a derived, read-only row.
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": reader, "role_key": "manager", "source": "manual"})
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": mentioned, "role_key": "member", "source": "system"})
	// Migration 469 backfills legacy `issue_permissions` rows as grants that name a
	// PERMISSION and leave role_key NULL — the table's CHECK allows exactly one of
	// the two. They carry this issue_id and a non-manual source, so the derived
	// query meets them; reading role_key there must not fail the whole read.
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": creator, "permission": "project.view", "source": "migration"})

	w := callIssueAccessEndpoint(testHandler.GetIssueAccessControl, issueAccessHTTPRequest(reader, ws, http.MethodGet, issue, "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read task access control: status=%d body=%s", w.Code, w.Body.String())
	}
	var state issueAccessControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &state); err != nil {
		t.Fatalf("decode task access control: %v", err)
	}
	if len(state.Grants) != 1 || state.Grants[0].SubjectID != reader {
		t.Fatalf("manual grants = %#v, want only the reader's manual row", state.Grants)
	}
	if len(state.DerivedGrants) != 1 {
		t.Fatalf("derived grants = %#v, want exactly the mention", state.DerivedGrants)
	}
	derived := state.DerivedGrants[0]
	if derived.SubjectID != mentioned || derived.Source != "system" || derived.Reason != "mention" {
		t.Fatalf("derived grant = %#v, want the mentioned member with reason mention", derived)
	}
}
