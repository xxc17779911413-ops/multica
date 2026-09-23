package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// The task creator is the immutable task Owner, and the Owner role carries
// IssueManage, so a creator must be able to read and change the task's access
// control even when they hold no manual grant and the task is restricted. This is
// the path a member relies on to grant a teammate access to a task they opened,
// and it is exactly what a share dialog that silently degrades to read-only
// hides; see the dialog's load-failure case.
func TestTaskCreatorKeepsManageOnTheirOwnTask(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	ws := dbfx.Workspace(t, "Creator manage", "creator-manage")
	fx := testutil.New(testPool, ws, testUserID)
	creator := dbfx.User(t, "Creator manage user", "creator-manage@example.test")
	fx.Member(t, ws, creator, "member")
	project := fx.Project(t, "Creator manage project")
	// Creator and assignee are the same person, with no manual grant at all.
	issue := fx.Issue(t, "Creator manage task", testutil.Cols{
		"project_id":    project,
		"creator_id":    creator,
		"assignee_type": "member",
		"assignee_id":   creator,
	})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)

	w := callIssueAccessEndpoint(testHandler.GetIssueAccessControl, issueAccessHTTPRequest(creator, ws, http.MethodGet, issue, "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("task creator cannot read the access control they own: status=%d body=%s", w.Code, w.Body.String())
	}

	// The dialog decides whether to offer the editor from the effective
	// permissions, so the manage permission must be part of what the read
	// reports — not merely implied by the 200.
	explain := callIssueAccessEndpoint(testHandler.GetIssueEffectiveAccess, issueAccessHTTPRequest(creator, ws, http.MethodGet, issue, "", nil))
	if explain.Code != http.StatusOK {
		t.Fatalf("task creator cannot read effective access: status=%d body=%s", explain.Code, explain.Body.String())
	}
	var effective struct {
		Permissions []string `json:"permissions"`
		Sources     []struct {
			Permission string `json:"permission"`
			Source     string `json:"source"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(explain.Body.Bytes(), &effective); err != nil {
		t.Fatalf("decode effective access: %v", err)
	}
	manageFromCreator := false
	for _, source := range effective.Sources {
		if source.Permission == string(projectauth.IssueManage) && source.Source == string(projectauth.AccessSourceCreator) {
			manageFromCreator = true
		}
	}
	if !manageFromCreator {
		t.Fatalf("creator is missing the manage permission from the creator source: %s", explain.Body.String())
	}
}
