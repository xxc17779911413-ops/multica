package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// Saving a manual grant must actually reach the resolver: the dialog's list shows
// picker selections and stored grants side by side, so a save that silently fails
// to take effect looks exactly like one that worked.
func TestSavedManualGrantYieldsManageToItsSubject(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	ws := dbfx.Workspace(t, "Saved grant", "saved-grant")
	fx := testutil.New(testPool, ws, testUserID)
	person := dbfx.User(t, "Saved grant person", "saved-grant-person@example.test")
	creator := dbfx.User(t, "Saved grant creator", "saved-grant-creator@example.test")
	for _, user := range []string{person, creator} {
		fx.Member(t, ws, user, "member")
	}
	project := fx.Project(t, "Saved grant project")
	issue := fx.Issue(t, "Saved grant task", testutil.Cols{"project_id": project, "creator_id": creator})
	// The workspace owner manages the task, which is what lets the save pass its
	// own gate; the person under test starts with no access at all.
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": creator, "role_key": "manager", "source": "manual"})

	actor := projectauth.Subject{UserID: creator, WorkspaceID: ws}
	tx, err := testPool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	request := issueAccessControlRequest{
		ExpectedVersion:   1,
		ProjectAccessMode: projectauth.ProjectAccessRestricted,
		Grants: []issueAccessControlGrant{
			{SubjectType: projectauth.SubjectUser, SubjectID: creator, Role: projectauth.RoleKey(projectauth.TaskManager), Scope: projectauth.RoleScopeTask},
			{SubjectType: projectauth.SubjectUser, SubjectID: person, Role: projectauth.RoleKey(projectauth.TaskManager), Scope: projectauth.RoleScopeTask},
		},
	}
	if _, _, err := testHandler.applyIssueAccessControl(context.Background(), tx, actor, issue, project, request); err != nil {
		_ = tx.Rollback(context.Background())
		t.Fatalf("apply access control: %v", err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	w := callIssueAccessEndpoint(testHandler.GetIssueEffectiveAccess, issueAccessHTTPRequest(person, ws, http.MethodGet, issue, "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read effective access: status=%d body=%s", w.Code, w.Body.String())
	}
	var effective struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &effective); err != nil {
		t.Fatalf("decode effective access: %v", err)
	}
	for _, permission := range effective.Permissions {
		if permission == string(projectauth.IssueManage) {
			return
		}
	}
	t.Fatalf("the saved manager grant did not give its subject manage: %s", w.Body.String())
}
