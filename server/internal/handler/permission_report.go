package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// 2026-08-24 coder(lq): Expose the permission report as a read-only endpoint
// in the workspace-scoped route group. Filter parsing stays at the HTTP edge;
// authorization and effective-permission rules remain in projectauth.Service.
func (h *Handler) ListPermissionReport(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	surface := "dashboard"
	if r.URL.Query().Get("export") == "true" {
		surface = "export"
	}
	defer func() { h.Metrics.ObserveProjectAuthorization(surface, time.Since(started)) }()
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permission report is disabled")
		return
	}
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	workspaceID := h.resolveWorkspaceID(r)
	if workspaceID == "" {
		writeError(w, http.StatusBadRequest, "workspace_id is required")
		return
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	q := r.URL.Query()
	filter := projectauth.PermissionReportFilter{
		WorkspaceID: workspaceID,
		ProjectID:   q.Get("project_id"),
		IssueID:     q.Get("issue_id"),
		UserID:      q.Get("user_id"),
		Role:        q.Get("role"),
		Permission:  projectauth.Permission(q.Get("permission")),
		SubjectType: projectauth.SubjectType(q.Get("subject_type")),
		SubjectID:   q.Get("subject_id"),
		Scope:       q.Get("scope"),
	}
	if raw := q.Get("limit"); raw != "" {
		filter.Limit, err = strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "limit must be an integer")
			return
		}
	}
	if raw := q.Get("offset"); raw != "" {
		filter.Offset, err = strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "offset must be an integer")
			return
		}
	}
	if filter.Limit <= 0 || filter.Limit > 1000 {
		filter.Limit = 1000
	}

	subject := projectauth.Subject{
		UserID:        userID,
		WorkspaceID:   workspaceID,
		WorkspaceRole: projectauth.WorkspaceRole(member.Role),
	}
	result, err := h.ProjectAuth.ListPermissionReport(r.Context(), subject, filter)
	if err != nil {
		switch {
		case errors.Is(err, projectauth.ErrInvalidReportFilter):
			writeErrorCode(w, http.StatusBadRequest, "invalid_permission_report_filter", "invalid permission report filter")
		case errors.Is(err, projectauth.ErrForbidden):
			writeErrorCode(w, http.StatusForbidden, "project_permission_report_forbidden", "insufficient project permissions")
		case errors.Is(err, projectauth.ErrNotWorkspaceMember), errors.Is(err, projectauth.ErrNoProjectAccess), errors.Is(err, projectauth.ErrCrossWorkspace):
			writeErrorCode(w, http.StatusNotFound, "project_not_found", "project not found")
		case projectPermissionSchemaMissing(err):
			// 2026-08-28 coder(lq): Older self-hosted instances can enable the
			// feature flag before migration 439 has run. Return an actionable
			// response instead of the generic report failure message.
			slog.Warn("project permission report requires migration 439",
				"workspace_id", workspaceID,
				"project_id", filter.ProjectID,
				"error", err,
			)
			writeErrorCode(w, http.StatusServiceUnavailable, "project_permission_migration_required", "project permission migration 439 is required")
		default:
			slog.Error("failed to load permission report",
				"workspace_id", workspaceID,
				"project_id", filter.ProjectID,
				"user_id", filter.UserID,
				"scope", filter.Scope,
				"error", err,
			)
			writeErrorCode(w, http.StatusInternalServerError, "project_permission_report_failed", "failed to load permission report")
		}
		return
	}
	if q.Get("export") == "true" {
		audit := (&projectAuthRepository{db: h.DB}).RecordAuthorizationAudit(r.Context(), projectauth.AuthorizationAuditEvent{
			WorkspaceID: workspaceID,
			IssueID:     filter.IssueID,
			ProjectID:   filter.ProjectID,
			ActorUserID: userID,
			Action:      "permission_report_exported",
			Details: map[string]any{
				"project_id": filter.ProjectID, "issue_id": filter.IssueID,
				"user_id": filter.UserID, "scope": filter.Scope, "row_count": len(result.Rows),
			},
		})
		if audit != nil {
			writeErrorCode(w, http.StatusInternalServerError, "permission_report_audit_failed", "failed to audit permission report export")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"rows":   result.Rows,
		"total":  result.Total,
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}
