package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// A person can hold several grants at once: a manager granted them access by
// hand, and a mention granted them a member role. Effective access is the union
// of those sources, so the higher role must win — the mention must not cap what
// the manual grant gave.
func TestEffectiveAccessUnionsManualAndMentionGrants(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	ws := dbfx.Workspace(t, "Union grants", "union-grants")
	fx := testutil.New(testPool, ws, testUserID)
	person := dbfx.User(t, "Union person", "union-person@example.test")
	creator := dbfx.User(t, "Union creator", "union-creator@example.test")
	for _, user := range []string{person, creator} {
		fx.Member(t, ws, user, "member")
	}
	project := fx.Project(t, "Union project")
	issue := fx.Issue(t, "Union task", testutil.Cols{"project_id": project, "creator_id": creator})
	fx.InsertNoID(t, "projectauth_issue_policies", testutil.Cols{"workspace_id": ws, "issue_id": issue, "project_access_mode": "restricted", "policy_version": 1}, "workspace_id=$1 AND issue_id=$2", ws, issue)
	// Granted by hand with a manager role…
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": person, "role_key": "manager", "source": "manual"})
	// …and mentioned, which stores the narrower member role.
	fx.Insert(t, "projectauth_access_grants", testutil.Cols{"workspace_id": ws, "project_id": project, "issue_id": issue, "subject_type": "user", "subject_id": person, "role_key": "member", "source": "system"})

	w := callIssueAccessEndpoint(testHandler.GetIssueEffectiveAccess, issueAccessHTTPRequest(person, ws, http.MethodGet, issue, "", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read effective access: status=%d body=%s", w.Code, w.Body.String())
	}
	var effective struct {
		Permissions []string `json:"permissions"`
		Sources     []struct {
			Permission string `json:"permission"`
			Source     string `json:"source"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &effective); err != nil {
		t.Fatalf("decode effective access: %v", err)
	}
	manageFromManual := false
	for _, source := range effective.Sources {
		if source.Permission == string(projectauth.IssueManage) && source.Source == string(projectauth.AccessSourceIssueDirect) {
			manageFromManual = true
		}
	}
	if !manageFromManual {
		t.Fatalf("the manual manager grant did not yield manage: %s", w.Body.String())
	}
}
