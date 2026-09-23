package handler

import (
	"encoding/json"
	"fmt"
	"testing"
)

// The project access dialog is offered to a project manager, so the flag that
// decides whether they may use it has to agree. It reported can_manage=false for
// managers because the seeded matrix gave project.member.manage to the owner
// alone, which left a manager staring at a dialog that refused them.
func TestProjectManagerCanManageProjectAccess(t *testing.T) {
	enableProjectAuthorizationForTest(t)
	projectID := dbfx.Project(t, "Manager manages access")
	managerID := dbfx.User(t, "Access manager", fmt.Sprintf("access-manager-%s@multica.test", t.Name()))
	memberID := dbfx.User(t, "Access member", fmt.Sprintf("access-member-%s@multica.test", t.Name()))
	for _, userID := range []string{managerID, memberID} {
		dbfx.Member(t, testWorkspaceID, userID, "member")
	}
	// Grant the roles the way the product does: through the service, so the
	// unified grant the permission check reads is the one under test.
	for _, grant := range []struct{ userID, role string }{{managerID, "manager"}, {memberID, "member"}} {
		req := withURLParam(newRequest("POST", "/api/projects/"+projectID+"/members", map[string]any{
			"user_id": grant.userID,
			"role":    grant.role,
		}), "id", projectID)
		if w := callIssueAccessEndpoint(testHandler.AddProjectMember, req); w.Code != 204 {
			t.Fatalf("grant %s as %s: status=%d body=%s", grant.role, grant.userID, w.Code, w.Body.String())
		}
	}

	canManage := func(userID string) bool {
		t.Helper()
		req := withURLParam(newRequestAs(userID, "GET", "/api/projects/"+projectID+"/members", nil), "id", projectID)
		w := callIssueAccessEndpoint(testHandler.ListProjectMembers, req)
		if w.Code != 200 {
			t.Fatalf("list project members as %s: status=%d body=%s", userID, w.Code, w.Body.String())
		}
		var body struct {
			CanManage bool `json:"can_manage"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode project members: %v", err)
		}
		return body.CanManage
	}

	if !canManage(managerID) {
		t.Error("a project manager cannot manage project access, so the dialog they are offered refuses them")
	}
	if canManage(memberID) {
		t.Error("a plain project member can manage project access")
	}
}
