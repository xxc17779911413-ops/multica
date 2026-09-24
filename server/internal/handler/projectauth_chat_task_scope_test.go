package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetIssue_ChatTaskScopedToInitiator pins the information-boundary rule
// for chat: an agent task spawned from a chat acts as the human who started
// the conversation (EnqueueChatTask stores initiatorUserID as the task's
// originator), so it can read exactly what that human can read -- never more.
// A conversation started by a plain member without grants must not become a
// side channel to a restricted issue.
func TestGetIssue_ChatTaskScopedToInitiator(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	enableProjectAuthorizationForTest(t)

	// Restricted target: created by the owner and policy-marked restricted,
	// so nobody but the owner (and explicit grantees) can see it.
	createW := httptest.NewRecorder()
	createReq := newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, map[string]any{
		"title":    "chat-scope restricted target",
		"status":   "todo",
		"priority": "medium",
	})
	testHandler.CreateIssue(createW, createReq)
	if createW.Code != http.StatusCreated {
		t.Fatalf("CreateIssue: expected 201, got %d: %s", createW.Code, createW.Body.String())
	}
	var restricted IssueResponse
	if err := json.NewDecoder(createW.Body).Decode(&restricted); err != nil {
		t.Fatalf("decode restricted issue: %v", err)
	}
	dbfx.Exec(t, `INSERT INTO projectauth_issue_policies
		(workspace_id, issue_id, project_access_mode, policy_version, created_by, updated_by)
		VALUES ($1, $2, 'restricted', 1, $3, $3)`, testWorkspaceID, restricted.ID, testUserID)

	// A second, unrestricted issue the chatting member is allowed to read by
	// being its creator.
	memberID := dbfx.User(t, "Chat scope member", "chat-scope-member@multica.test")
	dbfx.Member(t, testWorkspaceID, memberID, "member")
	ownW := httptest.NewRecorder()
	ownReq := newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, map[string]any{
		"title":    "chat-scope member owned",
		"status":   "todo",
		"priority": "medium",
	})
	ownReq.Header.Set("X-User-ID", memberID)
	testHandler.CreateIssue(ownW, ownReq)
	if ownW.Code != http.StatusCreated {
		t.Fatalf("CreateIssue (member): expected 201, got %d: %s", ownW.Code, ownW.Body.String())
	}
	var owned IssueResponse
	if err := json.NewDecoder(ownW.Body).Decode(&owned); err != nil {
		t.Fatalf("decode owned issue: %v", err)
	}

	// Chat-style task: no issue binding, originator = the chatting member.
	agentID := createHandlerTestAgent(t, "chat-scope-agent", nil)
	taskID := createHandlerTestTaskForAgentOnIssue(t, agentID, "")
	dbfx.Exec(t, `UPDATE agent_task_queue SET originator_user_id = $1, accountable_user_id = $1 WHERE id = $2`, memberID, taskID)

	read := func(issueID string) int {
		w := httptest.NewRecorder()
		req := newRequest("GET", "/api/issues/"+issueID, nil)
		req = withURLParam(req, "id", issueID)
		req.Header.Set("X-User-ID", memberID)
		req.Header.Set("X-Agent-ID", agentID)
		req.Header.Set("X-Task-ID", taskID)
		testHandler.GetIssue(w, req)
		return w.Code
	}

	if got := read(restricted.ID); got == http.StatusOK {
		t.Fatalf("chat agent read a restricted issue its initiator cannot see (status %d): the chat must not widen the human's access", got)
	}
	if got := read(owned.ID); got != http.StatusOK {
		t.Fatalf("chat agent reading an issue its initiator owns: got %d, want 200", got)
	}
}
