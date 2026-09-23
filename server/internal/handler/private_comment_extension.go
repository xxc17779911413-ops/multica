package handler

import (
	"context"
	"net/http"

	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-09-12 coder(lq): Keep private comment authorization behind one adapter
// so upstream comment lifecycle changes do not need to embed private policy.
func (h *Handler) requirePrivateCommentAccess(w http.ResponseWriter, r *http.Request, issue db.Issue) bool {
	return h.requireIssueProjectPermission(w, r, issue, projectauth.IssueComment)
}

// 2026-09-12 coder(lq): Reconcile comment mentions through the same task-level
// access adapter for project-bound and projectless tasks.
func syncPrivateCommentMentionAccess(ctx context.Context, executor dbExecutor, issue db.Issue) error {
	projectID := ""
	if issue.ProjectID.Valid {
		projectID = uuidToString(issue.ProjectID)
	}
	return syncIssueMentionAccessWithExecutor(ctx, executor, uuidToString(issue.ID), projectID, issue.Description.String)
}
