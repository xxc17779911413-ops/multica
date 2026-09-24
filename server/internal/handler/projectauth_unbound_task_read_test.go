package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetIssue_UnboundTaskActsAsOriginator pins the fix for autopilot runs
// whose task carries no source issue: there is no AgentUse on a source issue
// left to re-check, so a by-ID read must fall back to the originator's own
// access -- the same principal /api/issues and /api/issues/search already
// authorize against. Before the fix these requests answered 404
// "project not found" while list/search returned the same rows, which broke
// every monitoring write-back (metadata/labels/comments) that starts with a
// read.
func TestGetIssue_UnboundTaskActsAsOriginator(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	enableProjectAuthorizationForTest(t)

	// Target issue created by the workspace owner: the workspace-owner
	// bypass satisfies the ordinary View gate for the originator.
	createW := httptest.NewRecorder()
	createReq := newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, map[string]any{
		"title":    "unbound-task read target",
		"status":   "todo",
		"priority": "medium",
	})
	testHandler.CreateIssue(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("CreateIssue: expected 201, got %d: %s", createW.Code, createW.Body.String())
	}
	var created IssueResponse
	if err := json.NewDecoder(createW.Body).Decode(&created); err != nil {
		t.Fatalf("decode created issue: %v", err)
	}

	agentID := createHandlerTestAgent(t, "unbound-read-agent", nil)
	taskID := createHandlerTestTaskForAgentOnIssue(t, agentID, "") // issue_id NULL
	dbfx.Exec(t, `UPDATE agent_task_queue SET originator_user_id = $1, accountable_user_id = $1 WHERE id = $2`, testUserID, taskID)

	w := httptest.NewRecorder()
	req := newRequest("GET", "/api/issues/"+created.ID, nil)
	req = withURLParam(req, "id", created.ID)
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Task-ID", taskID)
	testHandler.GetIssue(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("unbound autopilot task reading an authorized issue: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
