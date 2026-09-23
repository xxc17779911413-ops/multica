package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

func enableProjectAuthForTest(t *testing.T) {
	t.Helper()
	previous := testHandler.ProjectAuth
	testHandler.ProjectAuth = projectauth.New(newProjectAuthRepository(testPool), true)
	t.Cleanup(func() { testHandler.ProjectAuth = previous })
}

func projectRoleForTest(t *testing.T, projectID, userID string) string {
	t.Helper()
	var role string
	// 2026-09-11 coder(lq): Absence is the expected result for task-scoped
	// assignee/mention grants; keep this helper usable for both positive and
	// negative project-membership assertions.
	dbfx.QueryRow(t, `
		SELECT COALESCE((
			SELECT role
			FROM project_members
			WHERE project_id = $1 AND user_id = $2
		), '')
	`, projectID, userID).Scan(&role)
	return role
}

// 2026-09-05 coder(lq): Keep the project-list role query covered against the
// PostgreSQL text/uuid coercion regression that hid creator ownership after a
// service restart.
func TestCurrentProjectRolesIncludesProjectCreator(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	projectID := dbfx.Project(t, "Project creator role metadata", testutil.Cols{
		"created_by": testUserID,
	})

	repo := &projectAuthRepository{db: testPool}
	roles, err := repo.CurrentProjectRoles(
		context.Background(), testWorkspaceID, testUserID,
	)
	if err != nil {
		t.Fatalf("CurrentProjectRoles: %v", err)
	}
	if got := roles[projectID]; got != projectauth.ProjectOwner {
		t.Fatalf("creator project role = %q, want %q", got, projectauth.ProjectOwner)
	}
	if got, err := repo.ProjectRole(context.Background(), projectID, testUserID); err != nil || got != projectauth.ProjectOwner {
		t.Fatalf("creator direct project role = %q, err=%v, want %q", got, err, projectauth.ProjectOwner)
	}
}

// 2026-09-07 coder(lq): Project views must expose the same delete capability
// enforced by DeleteProject. An ordinary workspace member who created the
// project is its immutable Owner, while a project Viewer must remain denied.
func TestProjectResponsesExposeEffectiveDeleteCapability(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	creatorID := dbfx.User(t, "Project delete capability creator", fmt.Sprintf("project-delete-capability-creator-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, creatorID, "member")

	createRecorder := httptest.NewRecorder()
	createRequest := newRequestAs(creatorID, http.MethodPost, "/api/projects?workspace_id="+testWorkspaceID, map[string]any{
		"title": "Project delete capability",
	})
	testHandler.CreateProject(createRecorder, createRequest)
	if createRecorder.Code != http.StatusCreated {
		t.Fatalf("CreateProject: expected 201, got %d: %s", createRecorder.Code, createRecorder.Body.String())
	}
	var created ProjectResponse
	if err := json.NewDecoder(createRecorder.Body).Decode(&created); err != nil {
		t.Fatalf("decode CreateProject: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM project WHERE id = $1`, created.ID)
	})
	if created.CurrentUserRole == nil || *created.CurrentUserRole != string(projectauth.ProjectOwner) || !created.CanDelete {
		t.Fatalf("created project access = role %v, can_delete %v; want owner, true", created.CurrentUserRole, created.CanDelete)
	}

	listRecorder := httptest.NewRecorder()
	testHandler.ListProjects(listRecorder, newRequestAs(creatorID, http.MethodGet,
		"/api/projects?workspace_id="+testWorkspaceID, nil))
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("ListProjects: expected 200, got %d: %s", listRecorder.Code, listRecorder.Body.String())
	}
	var listResponse struct {
		Projects []ProjectResponse `json:"projects"`
	}
	if err := json.NewDecoder(listRecorder.Body).Decode(&listResponse); err != nil {
		t.Fatalf("decode ListProjects: %v", err)
	}
	foundCreatorProject := false
	for _, project := range listResponse.Projects {
		if project.ID == created.ID {
			foundCreatorProject = true
			if project.CurrentUserRole == nil || *project.CurrentUserRole != string(projectauth.ProjectOwner) || !project.CanDelete {
				t.Fatalf("listed creator project access = role %v, can_delete %v; want owner, true", project.CurrentUserRole, project.CanDelete)
			}
		}
	}
	if !foundCreatorProject {
		t.Fatalf("creator project %s missing from ListProjects", created.ID)
	}

	getCreatorRecorder := httptest.NewRecorder()
	getCreatorRequest := withURLParam(newRequestAs(creatorID, http.MethodGet,
		"/api/projects/"+created.ID+"?workspace_id="+testWorkspaceID, nil), "id", created.ID)
	testHandler.GetProject(getCreatorRecorder, getCreatorRequest)
	if getCreatorRecorder.Code != http.StatusOK {
		t.Fatalf("creator GetProject: expected 200, got %d: %s", getCreatorRecorder.Code, getCreatorRecorder.Body.String())
	}
	var creatorDetail ProjectResponse
	if err := json.NewDecoder(getCreatorRecorder.Body).Decode(&creatorDetail); err != nil {
		t.Fatalf("decode creator GetProject: %v", err)
	}
	if !creatorDetail.CanDelete {
		t.Fatal("creator GetProject can_delete = false, want true")
	}

	viewerID := dbfx.User(t, "Project delete capability viewer", fmt.Sprintf("project-delete-capability-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	if err := (&projectAuthRepository{db: testPool}).AddProjectMember(context.Background(), created.ID, viewerID, projectauth.ProjectViewer); err != nil {
		t.Fatalf("add project viewer: %v", err)
	}

	getViewerRecorder := httptest.NewRecorder()
	getViewerRequest := withURLParam(newRequestAs(viewerID, http.MethodGet,
		"/api/projects/"+created.ID+"?workspace_id="+testWorkspaceID, nil), "id", created.ID)
	testHandler.GetProject(getViewerRecorder, getViewerRequest)
	if getViewerRecorder.Code != http.StatusOK {
		t.Fatalf("viewer GetProject: expected 200, got %d: %s", getViewerRecorder.Code, getViewerRecorder.Body.String())
	}
	var viewerDetail ProjectResponse
	if err := json.NewDecoder(getViewerRecorder.Body).Decode(&viewerDetail); err != nil {
		t.Fatalf("decode viewer GetProject: %v", err)
	}
	if viewerDetail.CanDelete {
		t.Fatal("viewer GetProject can_delete = true, want false")
	}

	viewerDeleteRecorder := httptest.NewRecorder()
	viewerDeleteRequest := withURLParam(newRequestAs(viewerID, http.MethodDelete,
		"/api/projects/"+created.ID+"?workspace_id="+testWorkspaceID, nil), "id", created.ID)
	testHandler.DeleteProject(viewerDeleteRecorder, viewerDeleteRequest)
	if viewerDeleteRecorder.Code != http.StatusForbidden {
		t.Fatalf("viewer DeleteProject: expected 403, got %d: %s", viewerDeleteRecorder.Code, viewerDeleteRecorder.Body.String())
	}

	creatorDeleteRecorder := httptest.NewRecorder()
	creatorDeleteRequest := withURLParam(newRequestAs(creatorID, http.MethodDelete,
		"/api/projects/"+created.ID+"?workspace_id="+testWorkspaceID, nil), "id", created.ID)
	testHandler.DeleteProject(creatorDeleteRecorder, creatorDeleteRequest)
	if creatorDeleteRecorder.Code != http.StatusNoContent {
		t.Fatalf("creator DeleteProject: expected 204, got %d: %s", creatorDeleteRecorder.Code, creatorDeleteRecorder.Body.String())
	}
}

// 2026-09-05 coder(lq): Execute the real revoke statement against PostgreSQL
// so a future advisory-lock change cannot reintroduce uuid = text inference.
func TestDeleteAccessGrantRemovesManualMemberGrant(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	ctx := context.Background()
	projectID := dbfx.Project(t, "Project revoke SQL regression")
	otherUserID := dbfx.User(t, "Project revoke target", "project-revoke-target@multica.ai")
	dbfx.Member(t, testWorkspaceID, otherUserID, "member")

	var grantID string
	if err := testPool.QueryRow(ctx, `
		INSERT INTO projectauth_access_grants
			(workspace_id, project_id, subject_type, subject_id, role_key, source, granted_by)
		VALUES ($1, $2, 'user', $3, 'member', 'manual', $4)
		RETURNING id::text`, testWorkspaceID, projectID, otherUserID, testUserID).Scan(&grantID); err != nil {
		t.Fatalf("insert manual member grant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM projectauth_access_grants WHERE id = $1`, grantID)
	})

	repo := &projectAuthRepository{db: testPool}
	if err := repo.DeleteAccessGrant(ctx, testWorkspaceID, projectID, "", projectauth.SubjectUser, otherUserID, projectauth.RoleKey(projectauth.ProjectMember), ""); err != nil {
		t.Fatalf("DeleteAccessGrant: %v", err)
	}

	var remaining int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM projectauth_access_grants WHERE id = $1`, grantID).Scan(&remaining); err != nil {
		t.Fatalf("check revoked grant: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("revoked grant count = %d, want 0", remaining)
	}
}

// 2026-09-05 coder(lq): A project created before the creator-owner backfill
// must still expose its immutable owner in the authorization dialog.
func TestListAccessGrantsIncludesProjectCreatorWithoutPhysicalGrant(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	projectID := dbfx.Project(t, "Project creator grant listing", testutil.Cols{
		"created_by": testUserID,
	})
	dbfx.Exec(t, `DELETE FROM projectauth_access_grants WHERE project_id = $1`, projectID)

	repo := &projectAuthRepository{db: testPool}
	grants, err := repo.ListAccessGrants(context.Background(), testWorkspaceID, projectID, "")
	if err != nil {
		t.Fatalf("ListAccessGrants: %v", err)
	}

	found := false
	for _, grant := range grants {
		if grant.SubjectType == projectauth.SubjectUser && grant.SubjectID == testUserID && projectauth.ProjectRole(grant.Role) == projectauth.ProjectOwner {
			found = true
			if grant.Source != projectauth.GrantSourceSystem {
				t.Fatalf("creator grant source = %q, want %q", grant.Source, projectauth.GrantSourceSystem)
			}
		}
	}
	if !found {
		t.Fatalf("creator owner grant missing from project access list: %+v", grants)
	}
}

// 2026-09-05 coder(lq): The legacy project-members endpoint must use the same
// runtime creator fallback as the canonical grant dialog, so old projects can
// still be administered before any historical backfill is run.
func TestListProjectMembersIncludesProjectCreatorWithoutPhysicalGrant(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	projectID := dbfx.Project(t, "Project creator member listing", testutil.Cols{
		"created_by": testUserID,
	})
	dbfx.Exec(t, `DELETE FROM projectauth_access_grants WHERE project_id = $1`, projectID)

	repo := &projectAuthRepository{db: testPool}
	members, err := repo.ListProjectMembers(context.Background(), projectID)
	if err != nil {
		t.Fatalf("ListProjectMembers: %v", err)
	}

	found := false
	for _, member := range members {
		if member.UserID == testUserID && member.Role == projectauth.ProjectOwner {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("creator owner member missing from legacy project member list: %+v", members)
	}
}

// 2026-09-05 coder(lq): The legacy IssuePermission reader must observe the
// same immutable creator rules as the HTTP authorization path, even when no
// historical owner grant has been backfilled into the grants table.
func TestIssuePermissionIncludesProjectAndTaskCreatorsWithoutPhysicalGrant(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	taskCreatorID := dbfx.User(t, "Task creator compatibility", fmt.Sprintf("task-creator-compat-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, taskCreatorID, "member")
	otherID := dbfx.User(t, "Unrelated compatibility user", fmt.Sprintf("unrelated-compat-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, otherID, "member")
	projectID := dbfx.Project(t, "Creator compatibility permissions", testutil.Cols{
		"created_by": testUserID,
	})
	issueID := dbfx.Issue(t, "Creator compatibility task", testutil.Cols{
		"project_id":   projectID,
		"creator_type": "member",
		"creator_id":   taskCreatorID,
	})
	dbfx.Exec(t, `DELETE FROM projectauth_access_grants WHERE project_id = $1`, projectID)

	repo := &projectAuthRepository{db: testPool}
	for _, permission := range []projectauth.Permission{projectauth.View, projectauth.Edit, projectauth.IssueManage} {
		if allowed, err := repo.IssuePermission(context.Background(), issueID, taskCreatorID, permission); err != nil || !allowed {
			t.Fatalf("task creator %s = allowed %v, err %v; want true, nil", permission, allowed, err)
		}
		if allowed, err := repo.IssuePermission(context.Background(), issueID, testUserID, permission); err != nil || !allowed {
			t.Fatalf("project creator %s = allowed %v, err %v; want true, nil", permission, allowed, err)
		}
		if allowed, err := repo.IssuePermission(context.Background(), issueID, otherID, permission); err != nil || allowed {
			t.Fatalf("unrelated user %s = allowed %v, err %v; want false, nil", permission, allowed, err)
		}
	}
	if allowed, err := repo.IssuePermission(context.Background(), issueID, taskCreatorID, projectauth.IssueCreate); err != nil || allowed {
		t.Fatalf("task creator project permission = allowed %v, err %v; want false, nil", allowed, err)
	}
}

// 2026-09-04 coder(lq): Task automation is canonical in the unified grant
// table. Keep this helper explicit about task scope so a project grant cannot
// accidentally satisfy an assignee or mention assertion.
func issueSystemRoleForTest(t *testing.T, issueID, projectID, userID string) (role, permission, source string) {
	t.Helper()
	dbfx.QueryRow(t, `
		SELECT COALESCE(MAX(role_key), ''), COALESCE(MAX(permission), ''), COALESCE(MAX(source), '')
		FROM projectauth_access_grants
		WHERE issue_id = $1 AND project_id = $2 AND subject_type = 'user' AND subject_id = $3
		  AND source = 'system'`, issueID, projectID, userID).Scan(&role, &permission, &source)
	return role, permission, source
}

// 2026-09-05 coder(lq): Projectless tasks use the dedicated task ACL table;
// keep assertions separate from the project-bound grant helper so a missing
// project ID can never silently query the wrong authorization store.
func projectlessIssueSystemRoleForTest(t *testing.T, issueID, userID string) (role, source string) {
	t.Helper()
	dbfx.QueryRow(t, `
		SELECT COALESCE(MAX(role_key), ''), COALESCE(MAX(source), '')
		FROM projectauth_issue_access_grants
		WHERE issue_id = $1 AND subject_type = 'user' AND subject_id = $2
		  AND source = 'system'`, issueID, userID).Scan(&role, &source)
	return role, source
}

// 2026-09-06 coder(lq): Keep projectless automatic grants covered against
// PostgreSQL parameter inference: subject_id is text while granted_by is uuid,
// so these values must not share one positional parameter.
func TestUpsertProjectlessIssueAccessGrantUsesDistinctSubjectAndGranterParams(t *testing.T) {
	if testPool == nil {
		t.Skip("database not available")
	}

	issueID := dbfx.Issue(t, "Projectless automatic grant SQL regression")
	t.Cleanup(func() {
		_, _ = testPool.Exec(context.Background(), `DELETE FROM projectauth_issue_access_grants WHERE issue_id = $1`, issueID)
	})

	if err := upsertProjectlessIssueAccessGrant(context.Background(), testPool, issueID, testUserID, projectauth.TaskOwner); err != nil {
		t.Fatalf("upsertProjectlessIssueAccessGrant: %v", err)
	}
	role, source := projectlessIssueSystemRoleForTest(t, issueID, testUserID)
	if role != string(projectauth.TaskOwner) || source != string(projectauth.GrantSourceSystem) {
		t.Fatalf("projectless creator grant = (%q, %q), want (%q, %q)", role, source, projectauth.TaskOwner, projectauth.GrantSourceSystem)
	}
}

// 2026-08-27 coder(lq): Project lead updates and project descriptions are
// authorization events, so they must grant owner and viewer roles atomically.
func TestProjectUpdatePromotesMemberLeadAndMention(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	leadID := dbfx.User(t, "Project lead", fmt.Sprintf("project-lead-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, leadID, "member")
	viewerID := dbfx.User(t, "Project viewer", fmt.Sprintf("project-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	projectID := dbfx.Project(t, "Automatic project roles")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPut, "/api/projects/"+projectID+"?workspace_id="+testWorkspaceID, map[string]any{
		"lead_type":   "member",
		"lead_id":     leadID,
		"description": fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	})
	req = withURLParam(req, "id", projectID)
	testHandler.UpdateProject(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateProject: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := projectRoleForTest(t, projectID, leadID); got != "owner" {
		t.Fatalf("project lead role = %q, want owner", got)
	}
	if got := projectRoleForTest(t, projectID, viewerID); got != "viewer" {
		t.Fatalf("mentioned project member role = %q, want viewer", got)
	}
}

// 2026-08-27 coder(lq): Assigning a project task to a workspace member must
// grant project member access, including the ordinary non-description update.
func TestIssueUpdatePromotesMemberAssignee(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	assigneeID := dbfx.User(t, "Issue assignee", fmt.Sprintf("issue-assignee-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, assigneeID, "member")
	projectID := dbfx.Project(t, "Automatic assignee role")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)
	issueID := dbfx.Issue(t, "Assign me", testutil.Cols{"project_id": projectID})

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPut, "/api/issues/"+issueID+"?workspace_id="+testWorkspaceID, map[string]any{
		"assignee_type": "member",
		"assignee_id":   assigneeID,
	})
	req = withURLParam(req, "id", issueID)
	testHandler.UpdateIssue(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateIssue: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	role, permission, source := issueSystemRoleForTest(t, issueID, projectID, assigneeID)
	if role != "member" || permission != "" || source != "system" {
		t.Fatalf("issue assignee task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
	}
	if got := projectRoleForTest(t, projectID, assigneeID); got != "" {
		t.Fatalf("issue assignee unexpectedly received project role %q", got)
	}
}

// 2026-08-27 coder(lq): Assignment is task-scoped: a new assignee receives
// the task Member role while any existing project role remains untouched.
func TestIssueUpdateAssigneePromotionPreservesStrongerProjectRoles(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	projectID := dbfx.Project(t, "Monotonic assignee roles")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)
	issueID := dbfx.Issue(t, "Assign with role promotion", testutil.Cols{"project_id": projectID})

	cases := []struct {
		name        string
		initialRole string
		wantRole    string
	}{
		{name: "no grant", wantRole: ""},
		{name: "viewer grant", initialRole: "viewer", wantRole: "viewer"},
		{name: "member grant", initialRole: "member", wantRole: "member"},
		{name: "manager grant", initialRole: "manager", wantRole: "manager"},
		{name: "owner grant", initialRole: "owner", wantRole: "owner"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assigneeID := dbfx.User(t, "Role assignee", fmt.Sprintf("role-assignee-%s-%d@multica.test", t.Name(), i))
			dbfx.Member(t, testWorkspaceID, assigneeID, "member")
			if tc.initialRole != "" {
				dbfx.InsertNoID(t, "project_members", testutil.Cols{
					"project_id": projectID,
					"user_id":    assigneeID,
					"role":       tc.initialRole,
				}, "project_id = $1 AND user_id = $2", projectID, assigneeID)
			}

			w := httptest.NewRecorder()
			req := newRequest(http.MethodPut, "/api/issues/"+issueID+"?workspace_id="+testWorkspaceID, map[string]any{
				"assignee_type": "member",
				"assignee_id":   assigneeID,
			})
			req = withURLParam(req, "id", issueID)
			testHandler.UpdateIssue(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("UpdateIssue: expected 200, got %d: %s", w.Code, w.Body.String())
			}
			role, permission, source := issueSystemRoleForTest(t, issueID, projectID, assigneeID)
			if role != "member" || permission != "" || source != "system" {
				t.Fatalf("issue assignee task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
			}
			if got := projectRoleForTest(t, projectID, assigneeID); got != tc.wantRole {
				t.Fatalf("existing project role = %q, want %q", got, tc.wantRole)
			}
		})
	}
}

// 2026-08-27 coder(lq): Task creation must apply both task access rules before
// commit: the assignee and a human mentioned in the description receive only
// the current task's Member role.
func TestCreateIssuePromotesAssigneeAndMentionedMember(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	assigneeID := dbfx.User(t, "Created issue assignee", fmt.Sprintf("created-issue-assignee-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, assigneeID, "member")
	viewerID := dbfx.User(t, "Created issue viewer", fmt.Sprintf("created-issue-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	projectID := dbfx.Project(t, "Created issue automatic roles")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)

	w := httptest.NewRecorder()
	testHandler.CreateIssue(w, newRequest(http.MethodPost, "/api/issues?workspace_id="+testWorkspaceID, map[string]any{
		"title":         "New task with inherited project access",
		"project_id":    projectID,
		"assignee_type": "member",
		"assignee_id":   assigneeID,
		"description":   fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	}))
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateIssue: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(w.Body).Decode(&created); err != nil || created.ID == "" {
		t.Fatalf("decode created issue: %v, body=%s", err, w.Body.String())
	}
	for name, userID := range map[string]string{"assignee": assigneeID, "mention": viewerID} {
		t.Run(name, func(t *testing.T) {
			role, permission, source := issueSystemRoleForTest(t, created.ID, projectID, userID)
			if role != "member" || permission != "" || source != "system" {
				t.Fatalf("task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
			}
			if projectRoleForTest(t, projectID, userID) != "" {
				t.Fatalf("task automation unexpectedly created project grant for %s", userID)
			}
		})
	}
	// 2026-09-04 coder(lq): The creator receives task Owner access, so turning
	// off the workspace-owner bypass cannot hide a task they created.
	role, permission, source := issueSystemRoleForTest(t, created.ID, projectID, testUserID)
	if role != "owner" || permission != "" || source != "system" {
		t.Fatalf("task creator grant = (%q, %q, %q), want (owner, empty, system)", role, permission, source)
	}
}

// 2026-09-09 coder(lq): A task filed by an Agent on behalf of a direct human
// must give that human task-level Member access. Otherwise the websocket can
// raise a native notification that the inbox REST refresh immediately hides.
func TestSyncIssueAccessGrantsDelegatedOriginatorTaskMember(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	ctx := context.Background()
	originatorID := dbfx.User(t, "Delegated task originator", fmt.Sprintf("delegated-task-originator-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, originatorID, "member")
	runtimeID := dbfx.Runtime(t, "Delegated task runtime")
	agentID := dbfx.Agent(t, "Delegated task agent", runtimeID)
	originTaskID := dbfx.Task(t, agentID, testutil.Cols{
		"runtime_id":          runtimeID,
		"originator_user_id":  originatorID,
		"accountable_user_id": originatorID,
		"originator_source":   "direct_human",
	})

	cases := []struct {
		name        string
		withProject bool
	}{
		{name: "project task", withProject: true},
		{name: "projectless task", withProject: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cols := testutil.Cols{
				"creator_type": "agent",
				"creator_id":   agentID,
				"origin_type":  "agent_create",
				"origin_id":    originTaskID,
			}
			projectID := ""
			if tc.withProject {
				projectID = dbfx.Project(t, "Delegated task project "+tc.name)
				cols["project_id"] = projectID
			}

			issueID := dbfx.Issue(t, "Delegated task "+tc.name, cols)
			dbfx.Cleanup(t, `DELETE FROM issue_permissions WHERE issue_id=$1`, issueID)
			dbfx.Cleanup(t, `DELETE FROM projectauth_access_grants WHERE issue_id=$1`, issueID)
			dbfx.Cleanup(t, `DELETE FROM projectauth_issue_access_grants WHERE issue_id=$1`, issueID)

			issue, err := testHandler.Queries.GetIssue(ctx, parseUUID(issueID))
			if err != nil {
				t.Fatalf("load delegated issue: %v", err)
			}
			if err := syncIssueAccessWithExecutor(ctx, testPool, nil, issue); err != nil {
				t.Fatalf("sync delegated issue access: %v", err)
			}

			if tc.withProject {
				role, permission, source := issueSystemRoleForTest(t, issueID, projectID, originatorID)
				if role != "member" || permission != "" || source != "system" {
					t.Fatalf("delegated task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
				}
				if got := dbfx.Count(t, `SELECT count(*) FROM project_members WHERE project_id=$1 AND user_id=$2`, projectID, originatorID); got != 0 {
					t.Fatalf("delegated originator project membership count = %d, want 0", got)
				}
			} else {
				role, source := projectlessIssueSystemRoleForTest(t, issueID, originatorID)
				if role != "member" || source != "system" {
					t.Fatalf("projectless delegated task grant = (%q, %q), want (member, system)", role, source)
				}
			}

			repo := &projectAuthRepository{db: testPool}
			for _, permission := range []projectauth.Permission{projectauth.View, projectauth.IssueComment} {
				if allowed, err := repo.IssuePermission(ctx, issueID, originatorID, permission); err != nil || !allowed {
					t.Fatalf("delegated originator %s = allowed %v, err %v; want true, nil", permission, allowed, err)
				}
			}

			siblingCols := testutil.Cols{"creator_type": "agent", "creator_id": agentID}
			if tc.withProject {
				siblingCols["project_id"] = projectID
			}
			siblingID := dbfx.Issue(t, "Unrelated sibling "+tc.name, siblingCols)
			if allowed, err := repo.IssuePermission(ctx, siblingID, originatorID, projectauth.View); err != nil || allowed {
				t.Fatalf("unrelated sibling view = allowed %v, err %v; want false, nil", allowed, err)
			}
		})
	}
}

// 2026-08-27 coder(lq): A human mentioned in a task comment receives Member
// access on that task only, before the comment becomes visible downstream.
func TestCreateCommentPromotesMentionedMember(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	viewerID := dbfx.User(t, "Comment viewer", fmt.Sprintf("comment-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	projectID := dbfx.Project(t, "Automatic comment role")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)
	issueID := dbfx.Issue(t, "Mention a reviewer", testutil.Cols{"project_id": projectID})

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/api/issues/"+issueID+"/comments?workspace_id="+testWorkspaceID, map[string]any{
		"content": fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	})
	req = withURLParam(req, "id", issueID)
	testHandler.CreateComment(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateComment: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	role, permission, source := issueSystemRoleForTest(t, issueID, projectID, viewerID)
	if role != "member" || permission != "" || source != "system" {
		t.Fatalf("comment mention task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
	}
	if got := projectRoleForTest(t, projectID, viewerID); got != "" {
		t.Fatalf("comment mention unexpectedly created project grant = %q", got)
	}
	// 2026-09-05 coder(lq): Verify the authorization read path, not only the
	// materialized row. A mention must make the person able to open and comment
	// on this task while leaving unrelated workspace members denied.
	repo := &projectAuthRepository{db: testPool}
	for _, permission := range []projectauth.Permission{projectauth.View, projectauth.IssueComment} {
		if allowed, err := repo.IssuePermission(context.Background(), issueID, viewerID, permission); err != nil || !allowed {
			t.Fatalf("mentioned member %s = allowed %v, err %v; want true, nil", permission, allowed, err)
		}
	}
	otherID := dbfx.User(t, "Unmentioned comment member", fmt.Sprintf("unmentioned-comment-member-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, otherID, "member")
	if allowed, err := repo.IssuePermission(context.Background(), issueID, otherID, projectauth.View); err != nil || allowed {
		t.Fatalf("unmentioned member view = allowed %v, err %v; want false, nil", allowed, err)
	}
}

// 2026-09-05 coder(lq): A comment @mention on a projectless task must be
// persisted as a task-scoped Member grant. This is the regression case for
// the empty project_id path that previously had no row to inspect.
func TestCreateCommentPromotesMentionedMemberForProjectlessIssue(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	viewerID := dbfx.User(t, "Projectless comment viewer", fmt.Sprintf("projectless-comment-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	issueID := dbfx.Issue(t, "Projectless mention task", testutil.Cols{})

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPost, "/api/issues/"+issueID+"/comments?workspace_id="+testWorkspaceID, map[string]any{
		"content": fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	})
	req = withURLParam(req, "id", issueID)
	testHandler.CreateComment(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("CreateComment projectless: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	role, source := projectlessIssueSystemRoleForTest(t, issueID, viewerID)
	if role != "member" || source != "system" {
		t.Fatalf("projectless comment mention task grant = (%q, %q), want (member, system)", role, source)
	}
	// 2026-09-05 coder(lq): Projectless tasks use the dedicated task ACL table,
	// so verify that the same @ grant is effective when the detail/list reader
	// asks for task permissions.
	repo := &projectAuthRepository{db: testPool}
	for _, permission := range []projectauth.Permission{projectauth.View, projectauth.IssueComment} {
		if allowed, err := repo.IssuePermission(context.Background(), issueID, viewerID, permission); err != nil || !allowed {
			t.Fatalf("projectless mentioned member %s = allowed %v, err %v; want true, nil", permission, allowed, err)
		}
	}
	otherID := dbfx.User(t, "Unmentioned projectless member", fmt.Sprintf("unmentioned-projectless-member-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, otherID, "member")
	if allowed, err := repo.IssuePermission(context.Background(), issueID, otherID, projectauth.View); err != nil || allowed {
		t.Fatalf("projectless unmentioned member view = allowed %v, err %v; want false, nil", allowed, err)
	}
}

// 2026-09-04 coder(lq): Keep Agent mention reconciliation on a single pgx
// transaction connection. This regression test fails with "conn busy" when
// the owner lookup runs before the comment result set has been closed.
func TestSyncIssueMentionAccessMaterializesCommentsBeforeAgentLookup(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	ownerID := dbfx.User(t, "Mentioned agent owner", fmt.Sprintf("mentioned-agent-owner-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, ownerID, "member")
	projectID := dbfx.Project(t, "Agent mention connection safety")
	issueID := dbfx.Issue(t, "Agent mention connection safety issue", testutil.Cols{"project_id": projectID})
	agentID := dbfx.Agent(t, "Mentioned agent", "", testutil.Cols{"owner_id": ownerID})

	ctx := context.Background()
	tx, err := testPool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `
		INSERT INTO comment (issue_id, workspace_id, author_type, author_id, content, type)
		VALUES ($1, $2, 'member', $3, $4, 'comment')`,
		issueID, testWorkspaceID, testUserID,
		fmt.Sprintf("Please review [@Agent](mention://agent/%s)", agentID))
	if err != nil {
		t.Fatalf("insert comment: %v", err)
	}

	if err := syncIssueMentionAccessWithExecutor(ctx, tx, issueID, projectID, ""); err != nil {
		t.Fatalf("sync agent mention access: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit transaction: %v", err)
	}

	var grantCount int
	if err := testPool.QueryRow(ctx, `
		SELECT COUNT(*) FROM projectauth_access_grants
		WHERE issue_id=$1 AND project_id=$2 AND subject_type='user' AND subject_id=$3
		  AND role_key='member' AND permission IS NULL AND source='system'`, issueID, projectID, ownerID).Scan(&grantCount); err != nil {
		t.Fatalf("check mention grant: %v", err)
	}
	if grantCount != 1 {
		t.Fatalf("mention grant count = %d, want 1", grantCount)
	}
}

// 2026-08-27 coder(lq): Editing an existing task comment can introduce a new
// member mention, so that edit grants the same task Member role as a newly
// created comment.
func TestUpdateCommentPromotesMentionedMember(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	viewerID := dbfx.User(t, "Edited comment viewer", fmt.Sprintf("edited-comment-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	projectID := dbfx.Project(t, "Edited comment automatic role")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)
	issueID := dbfx.Issue(t, "Mention a reviewer by editing", testutil.Cols{"project_id": projectID})
	commentID := dbfx.Comment(t, issueID, "Review needed")
	var initialCount int
	dbfx.QueryRow(t, `SELECT COUNT(*) FROM project_members WHERE project_id = $1 AND user_id = $2`, projectID, viewerID).Scan(&initialCount)
	if initialCount != 0 {
		t.Fatalf("mentioned member unexpectedly had project access before edit")
	}

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPut, "/api/comments/"+commentID+"?workspace_id="+testWorkspaceID, map[string]any{
		"content": fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	})
	req = withURLParam(req, "commentId", commentID)
	testHandler.UpdateComment(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateComment: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	role, permission, source := issueSystemRoleForTest(t, issueID, projectID, viewerID)
	if role != "member" || permission != "" || source != "system" {
		t.Fatalf("edited comment mention task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
	}
	if got := projectRoleForTest(t, projectID, viewerID); got != "" {
		t.Fatalf("edited comment mention unexpectedly created project grant = %q", got)
	}
}

// 2026-09-05 coder(lq): Editing a comment on a projectless task follows the
// same task-only grant path as comment creation, including mention removal.
func TestUpdateCommentPromotesMentionedMemberForProjectlessIssue(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	viewerID := dbfx.User(t, "Projectless edited comment viewer", fmt.Sprintf("projectless-edited-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	issueID := dbfx.Issue(t, "Projectless edited mention task", testutil.Cols{})
	commentID := dbfx.Comment(t, issueID, "Review needed")

	w := httptest.NewRecorder()
	req := newRequest(http.MethodPut, "/api/comments/"+commentID+"?workspace_id="+testWorkspaceID, map[string]any{
		"content": fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	})
	req = withURLParam(req, "commentId", commentID)
	testHandler.UpdateComment(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateComment projectless: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	role, source := projectlessIssueSystemRoleForTest(t, issueID, viewerID)
	if role != "member" || source != "system" {
		t.Fatalf("projectless edited comment mention task grant = (%q, %q), want (member, system)", role, source)
	}
	repo := &projectAuthRepository{db: testPool}
	if allowed, err := repo.IssuePermission(context.Background(), issueID, viewerID, projectauth.View); err != nil || !allowed {
		t.Fatalf("projectless edited mention view = allowed %v, err %v; want true, nil", allowed, err)
	}

	w = httptest.NewRecorder()
	req = newRequest(http.MethodPut, "/api/comments/"+commentID+"?workspace_id="+testWorkspaceID, map[string]any{
		"content": "Mention removed",
	})
	req = withURLParam(req, "commentId", commentID)
	testHandler.UpdateComment(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("UpdateComment projectless remove mention: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	role, source = projectlessIssueSystemRoleForTest(t, issueID, viewerID)
	if role != "" || source != "" {
		t.Fatalf("removed projectless mention still has automatic grant = (%q, %q)", role, source)
	}
	if allowed, err := repo.IssuePermission(context.Background(), issueID, viewerID, projectauth.View); err != nil || allowed {
		t.Fatalf("removed projectless mention view = allowed %v, err %v; want false, nil", allowed, err)
	}
}

// 2026-08-27 coder(lq): Plugin content writes are another official task
// description entrypoint and must inherit the same task Member rule.
func TestPatchPluginIssuePromotesMentionedMember(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	enableProjectAuthForTest(t)

	viewerID := dbfx.User(t, "Plugin viewer", fmt.Sprintf("plugin-viewer-%s@multica.test", t.Name()))
	dbfx.Member(t, testWorkspaceID, viewerID, "member")
	projectID := dbfx.Project(t, "Plugin mention role")
	dbfx.InsertNoID(t, "project_members", testutil.Cols{
		"project_id": projectID,
		"user_id":    testUserID,
		"role":       "owner",
	}, "project_id = $1 AND user_id = $2", projectID, testUserID)
	issueID := dbfx.Issue(t, "Plugin mention", testutil.Cols{"project_id": projectID})
	installationID := installPluginForAction(t, []string{"issues:read", "issues:write"})

	w := httptest.NewRecorder()
	req := pluginActionRequest(http.MethodPatch, "/v1/issues/"+issueID, installationID, map[string]any{
		"description": fmt.Sprintf("Please review [@Viewer](mention://member/%s)", viewerID),
	}, map[string]string{"issue_ref": issueID})
	testHandler.PatchPluginIssue(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("PatchPluginIssue: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	role, permission, source := issueSystemRoleForTest(t, issueID, projectID, viewerID)
	if role != "member" || permission != "" || source != "system" {
		t.Fatalf("plugin mention task grant = (%q, %q, %q), want (member, empty, system)", role, permission, source)
	}
	if got := projectRoleForTest(t, projectID, viewerID); got != "" {
		t.Fatalf("plugin mention unexpectedly created project grant = %q", got)
	}
}
