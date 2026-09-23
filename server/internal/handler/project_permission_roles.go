package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

type projectPermissionRoleRequest struct {
	Key         string                   `json:"key"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Permissions []projectauth.Permission `json:"permissions"`
}

func (h *Handler) projectPermissionRoleSubject(w http.ResponseWriter, r *http.Request) (projectauth.Subject, bool) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return projectauth.Subject{}, false
	}
	workspaceID := h.resolveWorkspaceID(r)
	if workspaceID == "" {
		writeError(w, http.StatusBadRequest, "workspace_id is required")
		return projectauth.Subject{}, false
	}
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return projectauth.Subject{}, false
	}
	return projectauth.Subject{UserID: userID, WorkspaceID: workspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}, true
}

func (h *Handler) ListProjectPermissionRoles(w http.ResponseWriter, r *http.Request) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project permission roles not found")
		return
	}
	subject, ok := h.projectPermissionRoleSubject(w, r)
	if !ok {
		return
	}
	roles, err := h.ProjectAuth.ListRoles(r.Context(), subject)
	if err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope": projectauth.RoleScopeProject, "roles": roles})
}

func (h *Handler) CreateProjectPermissionRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project permission roles not found")
		return
	}
	subject, ok := h.projectPermissionRoleSubject(w, r)
	if !ok {
		return
	}
	var req projectPermissionRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid role payload")
		return
	}
	role := projectauth.RoleDefinition{Key: projectauth.ProjectRole(strings.TrimSpace(req.Key)), Name: strings.TrimSpace(req.Name), Description: strings.TrimSpace(req.Description), Permissions: req.Permissions}
	var created projectauth.RoleDefinition
	err := h.withProjectPermissionRoleTransaction(r.Context(), func(service *projectauth.Service) error {
		var err error
		created, err = service.CreateRole(r.Context(), subject, role)
		return err
	})
	if err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

func (h *Handler) UpdateProjectPermissionRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project permission roles not found")
		return
	}
	subject, ok := h.projectPermissionRoleSubject(w, r)
	if !ok {
		return
	}
	key := strings.TrimSpace(chi.URLParam(r, "key"))
	var req projectPermissionRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid role payload")
		return
	}
	role := projectauth.RoleDefinition{Key: projectauth.ProjectRole(strings.TrimSpace(req.Key)), Name: strings.TrimSpace(req.Name), Description: strings.TrimSpace(req.Description), Permissions: req.Permissions}
	var updated projectauth.RoleDefinition
	err := h.withProjectPermissionRoleTransaction(r.Context(), func(service *projectauth.Service) error {
		var err error
		updated, err = service.UpdateRole(r.Context(), subject, key, role)
		return err
	})
	if err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *Handler) DeleteProjectPermissionRole(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project permission roles not found")
		return
	}
	subject, ok := h.projectPermissionRoleSubject(w, r)
	if !ok {
		return
	}
	key := strings.TrimSpace(chi.URLParam(r, "key"))
	err := h.withProjectPermissionRoleTransaction(r.Context(), func(service *projectauth.Service) error {
		return service.DeleteRole(r.Context(), subject, key)
	})
	if err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) withProjectPermissionRoleTransaction(ctx context.Context, fn func(*projectauth.Service) error) error {
	if h.TxStarter == nil {
		return errors.New("project permission role update requires transaction starter")
	}
	tx, err := h.TxStarter.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(projectauth.New(newProjectAuthRepository(tx), true)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func writeProjectPermissionRoleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, projectauth.ErrInvalidRole):
		writeError(w, http.StatusBadRequest, "invalid project permission role")
	case errors.Is(err, projectauth.ErrForbidden):
		writeError(w, http.StatusForbidden, "workspace owner or admin permission required")
	case errors.Is(err, projectauth.ErrNotWorkspaceMember), errors.Is(err, projectauth.ErrCrossWorkspace):
		writeError(w, http.StatusNotFound, "workspace not found")
	case errors.Is(err, projectauth.ErrRoleInUse):
		writeError(w, http.StatusConflict, "project permission role is still in use")
	default:
		writeError(w, http.StatusInternalServerError, "failed to update project permission role")
	}
}
