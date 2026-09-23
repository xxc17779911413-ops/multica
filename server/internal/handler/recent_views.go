package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// maxRecentIssueViews caps the view-history read. The client only ever asks
// for a screenful of recent tasks; a larger limit is a bug or an attempt to
// enumerate, so clamp instead of honouring it.
const maxRecentIssueViews = 100

type recentIssueView struct {
	IssueID  string `json:"issue_id"`
	ViewedAt string `json:"viewed_at"`
}

// RecordIssueView marks one issue as viewed by the caller. POST
// /api/issues/{id}/view. The same read guards as GetIssue apply, so a task a
// member cannot open never enters their history. Agent task-token traffic is
// ignored: "recently viewed" means a human opened the task.
func (h *Handler) RecordIssueView(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	issue, ok := h.loadIssueForUser(w, r, chi.URLParam(r, "id"))
	if !ok {
		return
	}
	if r.Header.Get("X-Actor-Source") == "task_token" {
		writeJSON(w, http.StatusOK, map[string]any{"recorded": false})
		return
	}
	if _, err := h.DB.Exec(r.Context(), `
		INSERT INTO issue_view_events (workspace_id, user_id, issue_id, viewed_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (user_id, issue_id)
		DO UPDATE SET viewed_at = EXCLUDED.viewed_at, workspace_id = EXCLUDED.workspace_id`,
		issue.WorkspaceID, parseUUID(userID), issue.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to record issue view")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recorded": true})
}

// ListRecentIssueViews returns the caller's most recently viewed issues for a
// workspace, newest first. GET /api/issues/view-history?workspace_id=..&limit=..
// The client feeds these ids into the ordinary list query, so everything the
// issue list already enforces (visibility, window, filters) still applies.
func (h *Handler) ListRecentIssueViews(w http.ResponseWriter, r *http.Request) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	workspaceID := h.resolveWorkspaceID(r)
	if workspaceID == "" {
		writeError(w, http.StatusBadRequest, "workspace_id is required")
		return
	}
	wsUUID, ok := parseUUIDOrBadRequest(w, workspaceID, "workspace_id")
	if !ok {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > maxRecentIssueViews {
		limit = maxRecentIssueViews
	}
	rows, err := h.DB.Query(r.Context(), `
		SELECT issue_id, viewed_at
		FROM issue_view_events
		WHERE user_id = $1 AND workspace_id = $2
		ORDER BY viewed_at DESC
		LIMIT $3`, parseUUID(userID), wsUUID, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load recent issue views")
		return
	}
	defer rows.Close()
	views := make([]recentIssueView, 0, limit)
	for rows.Next() {
		var issueID pgtype.UUID
		var viewedAt pgtype.Timestamptz
		if err := rows.Scan(&issueID, &viewedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to load recent issue views")
			return
		}
		views = append(views, recentIssueView{
			IssueID:  uuidToString(issueID),
			ViewedAt: timestampToString(viewedAt),
		})
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load recent issue views")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"views": views})
}
