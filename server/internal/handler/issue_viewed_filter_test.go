package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// TestListIssuesViewedAtFilter pins the per-user viewed-time filter: the
// window matches only the CALLER's own view events, so "查看时间" can never
// surface another member's reading history.
func TestListIssuesViewedAtFilter(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}

	createW := httptest.NewRecorder()
	createReq := newRequest("POST", "/api/issues?workspace_id="+testWorkspaceID, map[string]any{
		"title":    "viewed-at window target",
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

	// The caller viewed it just now; another member also has a view event on
	// the same issue, which must never satisfy the caller's window.
	dbfx.Exec(t, `INSERT INTO issue_view_events (workspace_id, user_id, issue_id, viewed_at)
		VALUES ($1, $2, $3, now())`, testWorkspaceID, testUserID, created.ID)
	otherUser := dbfx.User(t, "Viewed filter other", "viewed-filter-other@multica.test")
	dbfx.Member(t, testWorkspaceID, otherUser, "member")

	listed := func(field string, start, end time.Time) map[string]any {
		q := url.Values{}
		q.Set("workspace_id", testWorkspaceID)
		q.Set("date_field", field)
		q.Set("date_start", start.Format(time.RFC3339Nano))
		q.Set("date_end", end.Format(time.RFC3339Nano))
		w := httptest.NewRecorder()
		req := newRequest("GET", "/api/issues?"+q.Encode(), nil)
		testHandler.ListIssues(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("ListIssues(%s): expected 200, got %d: %s", field, w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
			t.Fatalf("decode list response: %v", err)
		}
		return out
	}
	contains := func(out map[string]any, id string) bool {
		issues, _ := out["issues"].([]any)
		for _, raw := range issues {
			if row, ok := raw.(map[string]any); ok && row["id"] == id {
				return true
			}
		}
		return false
	}

	now := time.Now()
	if out := listed("viewed_at", now.Add(-time.Hour), now.Add(time.Hour)); !contains(out, created.ID) {
		t.Fatal("viewed_at window containing the caller's view event must return the issue")
	}
	if out := listed("viewed_at", now.Add(time.Hour), now.Add(2*time.Hour)); contains(out, created.ID) {
		t.Fatal("viewed_at window after the caller's view event must not return the issue")
	}
}
