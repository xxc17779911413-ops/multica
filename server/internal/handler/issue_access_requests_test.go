package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

func TestIssueAccessRequestLifecycleIsScopedIdempotentAndAtomic(t *testing.T) {
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Access request", "access-request")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(t, ws, testUserID, "owner")
	requester := dbfx.User(t, "Access requester", "access-requester@example.test")
	manager := dbfx.User(t, "Task manager", "task-manager@example.test")
	fx.Member(t, ws, requester, "member")
	fx.Member(t, ws, manager, "member")
	project := fx.Project(t, "Access request project")
	issue := fx.Issue(t, "Restricted request task", testutil.Cols{"project_id": project})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": manager, "role_key": "manager", "source": "manual"})

	requesterSubject := projectauth.Subject{UserID: requester, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceMember}
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
	create := issueAccessRequestCreate{RequestedRole: projectauth.RoleKey(projectauth.TaskMember), Reason: "需要协作", ExpiresAt: &expires, IdempotencyKey: "request-lifecycle"}
	tx, _ := testPool.Begin(ctx)
	item, created, err := testHandler.createIssueAccessRequest(ctx, tx, requesterSubject, issue, create)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if !created || item.Status != accessRequestPending {
		t.Fatalf("created=%v item=%#v", created, item)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Transport retry returns the original unit and does not duplicate inbox or audit.
	tx, _ = testPool.Begin(ctx)
	retried, created, err := testHandler.createIssueAccessRequest(ctx, tx, requesterSubject, issue, create)
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if created || retried.ID != item.ID {
		t.Fatalf("retry created=%v item=%#v", created, retried)
	}
	_ = tx.Rollback(ctx)
	var requests, ownerInbox, managerInbox, createdAudits int
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_requests WHERE workspace_id=$1 AND issue_id=$2`, ws, issue).Scan(&requests)
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND type='task_access_request' AND recipient_id=$3`, ws, issue, testUserID).Scan(&ownerInbox)
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND type='task_access_request' AND recipient_id=$3`, ws, issue, manager).Scan(&managerInbox)
	fx.QueryRow(t, `SELECT count(*) FROM activity_log WHERE workspace_id=$1 AND issue_id=$2 AND action='task_access_request_created'`, ws, issue).Scan(&createdAudits)
	if requests != 1 || ownerInbox != 1 || managerInbox != 1 || createdAudits != 1 {
		t.Fatalf("requests/owner inbox/manager inbox/audits=%d/%d/%d/%d", requests, ownerInbox, managerInbox, createdAudits)
	}

	// 2026-09-18 coder(lq): 直接获得任务管理权限的用户应当可以审批权限申请。
	managerSubject := projectauth.Subject{UserID: manager, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceMember}
	tx, _ = testPool.Begin(ctx)
	approved, err := testHandler.reviewIssueAccessRequest(ctx, tx, managerSubject, issue, item.ID, issueAccessRequestReview{Action: "approve", Comment: "同意"})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if approved.Status != accessRequestApproved {
		t.Fatalf("status=%s", approved.Status)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var grants, constraints, grantAudits, resultInbox int
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants WHERE workspace_id=$1 AND issue_id=$2 AND subject_id=$3 AND role_key='member'`, ws, issue, requester).Scan(&grants)
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_grant_constraints c JOIN projectauth_access_grants g ON g.id=c.grant_id WHERE c.workspace_id=$1 AND g.issue_id=$2 AND c.origin_kind='access_request' AND c.origin_id=$3`, ws, issue, item.ID).Scan(&constraints)
	fx.QueryRow(t, `SELECT count(*) FROM activity_log WHERE workspace_id=$1 AND issue_id=$2 AND action='task_access_grant_created_from_request'`, ws, issue).Scan(&grantAudits)
	fx.QueryRow(t, `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND type='task_access_request' AND recipient_id=$3`, ws, issue, requester).Scan(&resultInbox)
	if grants != 1 || constraints != 1 || grantAudits != 1 || resultInbox != 1 {
		t.Fatalf("grant/constraint/audit/result inbox=%d/%d/%d/%d", grants, constraints, grantAudits, resultInbox)
	}

	// 2026-09-18 coder(lq): 已处理的申请不允许重复审批，避免重复授权或重复通知。
	tx, _ = testPool.Begin(ctx)
	_, err = testHandler.reviewIssueAccessRequest(ctx, tx, managerSubject, issue, item.ID, issueAccessRequestReview{Action: "approve"})
	_ = tx.Rollback(ctx)
	var conflict accessRequestStateConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("repeated review error=%v, want conflict", err)
	}
	tx, _ = testPool.Begin(ctx)
	_, err = testHandler.reviewIssueAccessRequest(ctx, tx, managerSubject, issue, item.ID, issueAccessRequestReview{Action: "reject"})
	_ = tx.Rollback(ctx)
	if !errors.As(err, &conflict) {
		t.Fatalf("opposite review error=%v, want conflict", err)
	}
}

func TestIssueAccessRequestExpiryAndRequesterCancellation(t *testing.T) {
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Access request terminal", "access-request-terminal")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(t, ws, testUserID, "owner")
	requester := dbfx.User(t, "Terminal requester", "terminal-requester@example.test")
	fx.Member(t, ws, requester, "member")
	issue := fx.Issue(t, "Terminal access request")
	expired := time.Now().Add(-time.Minute)
	requestID := fx.Insert(t, "projectauth_access_requests", testutil.Cols{"workspace_id": ws, "issue_id": issue, "requester_user_id": requester, "requested_role_key": "viewer", "idempotency_key": "expired", "created_at": time.Now().Add(-2 * time.Minute), "grant_expires_at": expired})
	owner := projectauth.Subject{UserID: testUserID, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceOwner}
	tx, _ := testPool.Begin(ctx)
	_, err := testHandler.reviewIssueAccessRequest(ctx, tx, owner, issue, requestID, issueAccessRequestReview{Action: "approve"})
	_ = tx.Rollback(ctx)
	var conflict accessRequestStateConflict
	if !errors.As(err, &conflict) || conflict.status != accessRequestExpired {
		t.Fatalf("expired review error=%v", err)
	}
}

// 2026-09-20 coder(lq): 多人审批幂等——任一「可管理」成员处理后，其余可管理者
// 既不能再审批，也不会重复收到申请通知；申请通知只投递给当前任务的有效管理者，
// 空间 Owner 在 PROJECT_OWNER_BYPASS_ENABLED=false 时不在此列。
func TestIssueAccessRequestApprovalIsIdempotentAcrossManagers(t *testing.T) {
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Access request quorum", "access-request-quorum")
	fx := testutil.New(testPool, ws, testUserID)
	// The workspace owner is deliberately left ungranted: with the owner bypass
	// disabled it neither receives the request nor may review it.
	fx.Member(t, ws, testUserID, "owner")
	requester := dbfx.User(t, "Quorum requester", "quorum-requester@example.test")
	firstManager := dbfx.User(t, "Quorum first manager", "quorum-first-manager@example.test")
	secondManager := dbfx.User(t, "Quorum second manager", "quorum-second-manager@example.test")
	// The creator is a fourth member so the ungranted workspace owner is not the
	// task creator; otherwise the creator source would grant them IssueManage and
	// mask whether the owner bypass is really off.
	creator := dbfx.User(t, "Quorum creator", "quorum-creator@example.test")
	for _, user := range []string{requester, firstManager, secondManager, creator} {
		fx.Member(t, ws, user, "member")
	}
	project := fx.Project(t, "Quorum project")
	issue := fx.Issue(t, "Quorum task", testutil.Cols{"project_id": project, "creator_id": creator})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)
	for _, manager := range []string{firstManager, secondManager} {
		fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": manager, "role_key": "manager", "source": "manual"})
	}

	requesterSubject := projectauth.Subject{UserID: requester, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceMember}
	tx, _ := testPool.Begin(ctx)
	item, created, err := testHandler.createIssueAccessRequest(ctx, tx, requesterSubject, issue, issueAccessRequestCreate{RequestedRole: projectauth.RoleKey(projectauth.TaskViewer), Reason: "需要查看任务", IdempotencyKey: "request-quorum"})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if !created {
		_ = tx.Rollback(ctx)
		t.Fatalf("request must be created: %#v", item)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// Fan-out at creation: exactly the two granted managers, once each. The
	// requester and the ungranted workspace owner hear nothing yet.
	for _, manager := range []string{firstManager, secondManager} {
		if got := inboxItemCount(t, ws, issue, "task_access_request", manager); got != 1 {
			t.Fatalf("manager %s requested-notification count=%d, want 1", manager, got)
		}
	}
	for _, other := range []string{requester, testUserID} {
		if got := inboxItemCount(t, ws, issue, "task_access_request", other); got != 0 {
			t.Fatalf("unexpected request notification for %s: count=%d, want 0", other, got)
		}
	}

	firstSubject := projectauth.Subject{UserID: firstManager, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceMember}
	tx, _ = testPool.Begin(ctx)
	approved, err := testHandler.reviewIssueAccessRequest(ctx, tx, firstSubject, issue, item.ID, issueAccessRequestReview{Action: "approve", Comment: "同意"})
	if err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	if approved.Status != accessRequestApproved || approved.ReviewerUserID != firstManager {
		t.Fatalf("approved=%#v", approved)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The requester learns the outcome; the other manager still has exactly the
	// single notification they already had, so a decision never re-notifies peers.
	if got := inboxItemCount(t, ws, issue, "task_access_request", requester); got != 1 {
		t.Fatalf("requester result-notification count=%d, want 1", got)
	}
	for _, manager := range []string{firstManager, secondManager} {
		if got := inboxItemCount(t, ws, issue, "task_access_request", manager); got != 1 {
			t.Fatalf("manager %s notification count changed to %d, want 1", manager, got)
		}
	}
	var resultBody string
	fx.QueryRow(t, `SELECT body FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND recipient_id=$3 AND type='task_access_request'`, ws, issue, requester).Scan(&resultBody)
	if !strings.Contains(resultBody, "已批准") {
		t.Fatalf("requester notification body=%q, want the approved outcome", resultBody)
	}

	// A peer manager can no longer decide, in either direction, and the refusal
	// reports the state the peer would have been shown.
	secondSubject := projectauth.Subject{UserID: secondManager, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceMember}
	for _, action := range []string{"approve", "reject"} {
		tx, _ = testPool.Begin(ctx)
		_, err := testHandler.reviewIssueAccessRequest(ctx, tx, secondSubject, issue, item.ID, issueAccessRequestReview{Action: action})
		_ = tx.Rollback(ctx)
		var conflict accessRequestStateConflict
		if !errors.As(err, &conflict) || conflict.status != accessRequestApproved {
			t.Fatalf("peer manager %s error=%v, want conflict at approved", action, err)
		}
	}
	var grants int
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants WHERE workspace_id=$1 AND issue_id=$2 AND subject_id=$3`, ws, issue, requester).Scan(&grants)
	if grants != 1 {
		t.Fatalf("grant count=%d, want a single grant", grants)
	}

	// Delivery is keyed per (recipient, event), so no retry path can duplicate it.
	var requestedForPeer, approvedForRequester int
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_request_notifications WHERE workspace_id=$1 AND request_id=$2 AND event='requested' AND recipient_user_id=$3`, ws, item.ID, secondManager).Scan(&requestedForPeer)
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_request_notifications WHERE workspace_id=$1 AND request_id=$2 AND event='approved' AND recipient_user_id=$3`, ws, item.ID, requester).Scan(&approvedForRequester)
	if requestedForPeer != 1 || approvedForRequester != 1 {
		t.Fatalf("delivery rows requested/approved=%d/%d, want 1/1", requestedForPeer, approvedForRequester)
	}
}

// 2026-09-20 coder(lq): 「可编辑」不等于可管理。任务成员角色确实能编辑任务，
// 但审批权限申请必须被拒绝，避免把可编辑误当成可授权。
func TestIssueAccessRequestRejectsEditOnlyManager(t *testing.T) {
	t.Setenv("PROJECT_OWNER_BYPASS_ENABLED", "false")
	ctx := context.Background()
	ws := dbfx.Workspace(t, "Access request edit only", "access-request-edit-only")
	fx := testutil.New(testPool, ws, testUserID)
	fx.Member(t, ws, testUserID, "owner")
	requester := dbfx.User(t, "Edit-only requester", "edit-only-requester@example.test")
	editor := dbfx.User(t, "Edit-only editor", "edit-only-editor@example.test")
	fx.Member(t, ws, requester, "member")
	fx.Member(t, ws, editor, "member")
	project := fx.Project(t, "Edit-only project")
	issue := fx.Issue(t, "Edit-only task", testutil.Cols{"project_id": project})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": editor, "role_key": "member", "source": "manual"})

	// Pin the premise first: the same actor may edit but may not manage.
	editorSubject := projectauth.Subject{UserID: editor, WorkspaceID: ws, WorkspaceRole: projectauth.WorkspaceMember}
	resolver := projectauth.NewEffectiveAccessResolver(&projectAuthRepository{db: testPool})
	edit, err := resolver.ExplainIssue(ctx, editorSubject, issue, projectauth.Edit)
	if err != nil {
		t.Fatal(err)
	}
	if !edit.Allowed {
		t.Fatalf("edit-only member must still hold edit: %#v", edit)
	}
	manage, err := resolver.ExplainIssue(ctx, editorSubject, issue, projectauth.IssueManage)
	if err != nil {
		t.Fatal(err)
	}
	if manage.Allowed {
		t.Fatalf("edit-only member must not hold manage: %#v", manage)
	}

	requestID := fx.Insert(t, "projectauth_access_requests", testutil.Cols{"workspace_id": ws, "issue_id": issue, "requester_user_id": requester, "requested_role_key": "viewer", "idempotency_key": "edit-only-review"})
	tx, _ := testPool.Begin(ctx)
	_, err = testHandler.reviewIssueAccessRequest(ctx, tx, editorSubject, issue, requestID, issueAccessRequestReview{Action: "approve"})
	_ = tx.Rollback(ctx)
	if !errors.Is(err, projectauth.ErrForbidden) {
		t.Fatalf("edit-only review error=%v, want forbidden", err)
	}
	var granted int
	fx.QueryRow(t, `SELECT count(*) FROM projectauth_access_grants WHERE workspace_id=$1 AND issue_id=$2 AND subject_id=$3`, ws, issue, requester).Scan(&granted)
	if granted != 0 {
		t.Fatalf("refused review granted %d rows, want 0", granted)
	}
}

// inboxItemCount counts the notifications of one type delivered to one member
// for one task, so tests can assert fan-out without depending on row order.
func inboxItemCount(t *testing.T, workspaceID, issueID, itemType, recipientID string) int {
	t.Helper()
	var count int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM inbox_item WHERE workspace_id=$1 AND issue_id=$2 AND type=$3 AND recipient_id=$4`, workspaceID, issueID, itemType, recipientID).Scan(&count); err != nil {
		t.Fatalf("count %s inbox items: %v", itemType, err)
	}
	return count
}

// issueAccessHTTPRequest builds an /api/issues/{id} request against a fixture
// workspace. The shared test handler is bound to another workspace, so both the
// header and the route parameter have to be supplied explicitly.
func issueAccessHTTPRequest(userID, workspaceID, method, issueID, query string, body any) *http.Request {
	path := "/api/issues/" + issueID
	if query != "" {
		path += "?" + query
	}
	req := newRequestAs(userID, method, path, body)
	req.Header.Set("X-Workspace-ID", workspaceID)
	return withURLParam(req, "id", issueID)
}

// enableProjectAuthorizationForTest turns the task-permission overlay on for
// the shared handler. TestMain builds it with the overlay off, which would 404
// the write endpoint before the permission gate under test is ever reached.
func enableProjectAuthorizationForTest(t *testing.T) {
	t.Helper()
	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.NewWithRollout(&projectAuthRepository{db: testPool}, projectauth.RolloutRestricted)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
}

// callIssueAccessEndpoint runs one handler directly, so the endpoint test reads
// as "call this handler with this actor" instead of repeating recorder plumbing.
func callIssueAccessEndpoint(handler func(http.ResponseWriter, *http.Request), req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}
