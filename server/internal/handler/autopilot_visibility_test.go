package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func insertVisibilityAutopilot(t *testing.T, title, assigneeType, assigneeID, createdByID string) string {
	t.Helper()
	var id string
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO autopilot (
			workspace_id, title, assignee_type, assignee_id,
			status, execution_mode, created_by_type, created_by_id
		)
		VALUES ($1, $2, $3, $4, 'active', 'run_only', 'member', $5)
		RETURNING id
	`, testWorkspaceID, title, assigneeType, assigneeID, createdByID).Scan(&id); err != nil {
		t.Fatalf("insert visibility autopilot: %v", err)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(), `DELETE FROM autopilot WHERE id = $1`, id)
	})
	return id
}

func autopilotVisibleInList(t *testing.T, userID, autopilotID string) bool {
	t.Helper()
	w := httptest.NewRecorder()
	r := newRequestAs(userID, http.MethodGet, "/api/autopilots?workspace_id="+testWorkspaceID, nil)
	testHandler.ListAutopilots(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ListAutopilots: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Autopilots []AutopilotResponse `json:"autopilots"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode autopilot list: %v", err)
	}
	for _, autopilot := range body.Autopilots {
		if autopilot.ID == autopilotID {
			return true
		}
	}
	return false
}

func autopilotDetailStatus(t *testing.T, userID, autopilotID string) int {
	t.Helper()
	w := httptest.NewRecorder()
	r := newRequestAs(userID, http.MethodGet, "/api/autopilots/"+autopilotID+"?workspace_id="+testWorkspaceID, nil)
	r = withURLParam(r, "id", autopilotID)
	testHandler.GetAutopilot(w, r)
	return w.Code
}

// 2026-08-27 coder(lq): Pin the Autopilot data boundary in both collection
// and direct-resource paths. Only the creator, effective executor, and the
// workspace owner may discover an Autopilot; admin is intentionally not an
// owner-equivalent for this read policy.
func TestAutopilotVisibility_CreatorExecutorAndOwnerOnly(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	creatorID := createPlainMember(t, "ap-visibility-creator@multica.test")
	executorID := createPlainMember(t, "ap-visibility-executor@multica.test")
	strangerID := createPlainMember(t, "ap-visibility-stranger@multica.test")
	adminID := createPlainMember(t, "ap-visibility-admin@multica.test")
	if _, err := testPool.Exec(context.Background(), `UPDATE member SET role = 'admin' WHERE workspace_id = $1 AND user_id = $2`, testWorkspaceID, adminID); err != nil {
		t.Fatalf("promote admin fixture: %v", err)
	}

	agentID := createHandlerTestAgent(t, "ap-visibility-direct-agent", nil)
	if _, err := testPool.Exec(context.Background(), `UPDATE agent SET owner_id = $1 WHERE id = $2`, executorID, agentID); err != nil {
		t.Fatalf("assign agent owner: %v", err)
	}
	autopilotID := insertVisibilityAutopilot(t, "ap-visibility-direct", "agent", agentID, creatorID)

	tests := []struct {
		name    string
		userID  string
		visible bool
	}{
		{name: "workspace owner", userID: testUserID, visible: true},
		{name: "creator", userID: creatorID, visible: true},
		{name: "direct agent owner is executor", userID: executorID, visible: true},
		{name: "unrelated member", userID: strangerID, visible: false},
		{name: "admin without another relationship", userID: adminID, visible: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := autopilotVisibleInList(t, tt.userID, autopilotID); got != tt.visible {
				t.Fatalf("list visibility = %v, want %v", got, tt.visible)
			}
			wantStatus := http.StatusNotFound
			if tt.visible {
				wantStatus = http.StatusOK
			}
			if got := autopilotDetailStatus(t, tt.userID, autopilotID); got != wantStatus {
				t.Fatalf("detail status = %d, want %d", got, wantStatus)
			}
		})
	}
}

func TestAutopilotVisibility_SquadExecutorIsLeaderAgentOwner(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	executorID := createPlainMember(t, "ap-visibility-squad-executor@multica.test")
	strangerID := createPlainMember(t, "ap-visibility-squad-stranger@multica.test")
	leaderID := createHandlerTestAgent(t, "ap-visibility-squad-leader", nil)
	if _, err := testPool.Exec(context.Background(), `UPDATE agent SET owner_id = $1 WHERE id = $2`, executorID, leaderID); err != nil {
		t.Fatalf("assign leader owner: %v", err)
	}

	var squadID string
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO squad (workspace_id, name, description, leader_id, creator_id)
		VALUES ($1, 'AP Visibility Squad', '', $2, $3)
		RETURNING id
	`, testWorkspaceID, leaderID, testUserID).Scan(&squadID); err != nil {
		t.Fatalf("insert squad: %v", err)
	}
	t.Cleanup(func() {
		testPool.Exec(context.Background(), `DELETE FROM squad WHERE id = $1`, squadID)
	})

	autopilotID := insertVisibilityAutopilot(t, "ap-visibility-squad", "squad", squadID, testUserID)
	if !autopilotVisibleInList(t, executorID, autopilotID) {
		t.Fatal("squad leader agent owner should see the autopilot in the list")
	}
	if got := autopilotDetailStatus(t, executorID, autopilotID); got != http.StatusOK {
		t.Fatalf("squad executor detail status = %d, want 200", got)
	}
	if autopilotVisibleInList(t, strangerID, autopilotID) {
		t.Fatal("unrelated member should not see the squad autopilot")
	}
}

func TestAutopilotVisibility_CollaboratorDoesNotExpandReadScope(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	collaboratorID := createPlainMember(t, "ap-visibility-collaborator@multica.test")
	agentID := createHandlerTestAgent(t, "ap-visibility-collaborator-agent", nil)
	autopilotID := insertVisibilityAutopilot(t, "ap-visibility-collaborator", "agent", agentID, testUserID)
	if _, err := testPool.Exec(context.Background(), `
		INSERT INTO autopilot_collaborator (autopilot_id, user_type, user_id, granted_by)
		VALUES ($1, 'member', $2, $3)
	`, autopilotID, collaboratorID, testUserID); err != nil {
		t.Fatalf("insert collaborator: %v", err)
	}

	if autopilotVisibleInList(t, collaboratorID, autopilotID) {
		t.Fatal("collaborator grant must not expand the new read scope")
	}
	if got := autopilotDetailStatus(t, collaboratorID, autopilotID); got != http.StatusNotFound {
		t.Fatalf("collaborator detail status = %d, want 404", got)
	}
}

func TestAutopilotVisibility_SubresourcesInheritAutopilotBoundary(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	strangerID := createPlainMember(t, "ap-visibility-subresource-stranger@multica.test")
	agentID := createHandlerTestAgent(t, "ap-visibility-subresource-agent", nil)
	autopilotID := insertVisibilityAutopilot(t, "ap-visibility-subresources", "agent", agentID, testUserID)

	tests := []struct {
		name string
		path string
		call func(http.ResponseWriter, *http.Request)
	}{
		{name: "runs", path: "/api/autopilots/" + autopilotID + "/runs", call: testHandler.ListAutopilotRuns},
		{name: "deliveries", path: "/api/autopilots/" + autopilotID + "/deliveries", call: testHandler.ListAutopilotDeliveries},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := newRequestAs(strangerID, http.MethodGet, tt.path+"?workspace_id="+testWorkspaceID, nil)
			r = withURLParam(r, "id", autopilotID)
			tt.call(w, r)
			if w.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
			}
		})
	}
}

// 2026-08-27 coder(lq): Destructive routes must pass through the same hidden
// resource boundary as reads. Workspace admin status grants write capability
// only after visibility has been established; it must not reveal or mutate an
// unrelated creator's Autopilot through a guessed UUID.
func TestAutopilotVisibility_DeleteRoutesCannotBypassBoundary(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	adminID := createPlainMember(t, "ap-visibility-delete-admin@multica.test")
	if _, err := testPool.Exec(context.Background(), `UPDATE member SET role = 'admin' WHERE workspace_id = $1 AND user_id = $2`, testWorkspaceID, adminID); err != nil {
		t.Fatalf("promote admin fixture: %v", err)
	}
	agentID := createHandlerTestAgent(t, "ap-visibility-delete-agent", nil)
	autopilotID := insertVisibilityAutopilot(t, "ap-visibility-delete", "agent", agentID, testUserID)

	var triggerID string
	if err := testPool.QueryRow(context.Background(), `
		INSERT INTO autopilot_trigger (autopilot_id, kind, enabled)
		VALUES ($1, 'api', TRUE)
		RETURNING id
	`, autopilotID).Scan(&triggerID); err != nil {
		t.Fatalf("insert trigger: %v", err)
	}

	t.Run("delete trigger", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := newRequestAs(adminID, http.MethodDelete, "/api/autopilots/"+autopilotID+"/triggers/"+triggerID+"?workspace_id="+testWorkspaceID, nil)
		// 2026-09-20 coder(lq): withURLParam replaces the whole route context, so
		// two calls in a row dropped the parent id and the handler refused with
		// 400 "invalid autopilot id" instead of reaching the visibility guard.
		r = withURLParams(r, "id", autopilotID, "triggerId", triggerID)
		testHandler.DeleteAutopilotTrigger(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
		}
	})

	t.Run("delete autopilot", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := newRequestAs(adminID, http.MethodDelete, "/api/autopilots/"+autopilotID+"?workspace_id="+testWorkspaceID, nil)
		r = withURLParam(r, "id", autopilotID)
		testHandler.DeleteAutopilot(w, r)
		if w.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404: %s", w.Code, w.Body.String())
		}
	})
}
