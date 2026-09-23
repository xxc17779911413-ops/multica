package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

// ListProjectAuthorizationOrganizations serves the last synchronized,
// provider-neutral organization directory for the workspace. It intentionally
// does not contact DingTalk/WeCom/Feishu from an HTTP request.
// 2026-09-01 coder(lq): Add a safe organization picker endpoint.
func (h *Handler) ListProjectAuthorizationOrganizations(w http.ResponseWriter, r *http.Request) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeErrorCode(w, http.StatusNotFound, "project_permission_disabled", "project permissions are disabled")
		return
	}
	workspaceID := chi.URLParam(r, "id")
	if workspaceID == "" || h.resolveWorkspaceID(r) != workspaceID {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}
	userID, ok := requireUserID(w, r)
	if !ok {
		return
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}
	subject := projectauth.Subject{
		UserID:        userID,
		WorkspaceID:   workspaceID,
		WorkspaceRole: projectauth.WorkspaceRole(member.Role),
	}
	organizations, err := h.ProjectAuth.ListOrganizations(r.Context(), subject)
	if err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	members, err := h.ProjectAuth.ListOrganizationMembers(r.Context(), subject)
	if err != nil {
		writeProjectAccessGrantError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"organizations": organizations,
		"members":       members,
		"total":         len(organizations),
		"member_total":  len(members),
	})
}
