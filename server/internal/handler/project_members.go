package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/multica-ai/multica/server/pkg/projectauth"
)

type projectMemberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// 2026-08-27 coder(lq): Serialize explicit membership changes on the project
// row so two simultaneous owner removals/downgrades cannot leave zero owners.
func (h *Handler) updateProjectMembers(ctx context.Context, projectID string, update func(*projectauth.Service) error) error {
	if h.TxStarter == nil {
		return errors.New("project member update requires transaction starter")
	}
	tx, err := h.TxStarter.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var lockedID string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM project WHERE id = $1 FOR UPDATE`, projectID).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return projectauth.ErrNoProjectAccess
		}
		return err
	}
	service := projectauth.New(newProjectAuthRepository(tx), true)
	if err := update(service); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (h *Handler) projectSubject(w http.ResponseWriter, r *http.Request, projectID string) (projectauth.Subject, bool) {
	userID, ok := requireUserID(w, r)
	if !ok {
		return projectauth.Subject{}, false
	}
	workspaceID := h.resolveWorkspaceID(r)
	member, err := h.getWorkspaceMember(r.Context(), userID, workspaceID)
	if err != nil {
		writeError(w, http.StatusNotFound, "project not found")
		return projectauth.Subject{}, false
	}
	return projectauth.Subject{UserID: userID, WorkspaceID: workspaceID, WorkspaceRole: projectauth.WorkspaceRole(member.Role)}, true
}

func (h *Handler) ListProjectMembers(w http.ResponseWriter, r *http.Request) {
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	projectID := chi.URLParam(r, "id")
	subject, ok := h.projectSubject(w, r, projectID)
	if !ok {
		return
	}
	members, err := h.ProjectAuth.ListMembers(r.Context(), subject, projectID)
	if err != nil {
		writeProjectAuthError(w, err)
		return
	}
	canManage := h.ProjectAuth.Check(r.Context(), subject, projectID, projectauth.MemberManage) == nil
	writeJSON(w, http.StatusOK, map[string]any{"members": members, "total": len(members), "can_manage": canManage})
}

func (h *Handler) AddProjectMember(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	projectID := chi.URLParam(r, "id")
	subject, ok := h.projectSubject(w, r, projectID)
	if !ok {
		return
	}
	var req projectMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
		writeError(w, http.StatusBadRequest, "user_id is required")
		return
	}
	if err := h.updateProjectMembers(r.Context(), projectID, func(service *projectauth.Service) error {
		return service.AddMember(r.Context(), subject, projectID, req.UserID, projectauth.ProjectRole(req.Role))
	}); err != nil {
		writeProjectAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) RemoveProjectMember(w http.ResponseWriter, r *http.Request) {
	if !h.requireProjectAuthorizationEnabled(w) {
		return
	}
	if h.ProjectAuth == nil || !h.ProjectAuth.Enabled() {
		writeError(w, http.StatusNotFound, "project not found")
		return
	}
	projectID := chi.URLParam(r, "id")
	subject, ok := h.projectSubject(w, r, projectID)
	if !ok {
		return
	}
	if err := h.updateProjectMembers(r.Context(), projectID, func(service *projectauth.Service) error {
		return service.RemoveMember(r.Context(), subject, projectID, chi.URLParam(r, "userId"))
	}); err != nil {
		writeProjectAuthError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeProjectAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, projectauth.ErrInvalidRole):
		writeError(w, http.StatusBadRequest, "invalid project role")
	case errors.Is(err, projectauth.ErrForbidden):
		writeError(w, http.StatusForbidden, "insufficient project permissions")
	case errors.Is(err, projectauth.ErrLastOwner):
		writeError(w, http.StatusConflict, "project must retain at least one owner")
	case errors.Is(err, projectauth.ErrNotWorkspaceMember), errors.Is(err, projectauth.ErrNoProjectAccess), errors.Is(err, projectauth.ErrCrossWorkspace):
		writeError(w, http.StatusNotFound, "project not found")
	default:
		writeError(w, http.StatusInternalServerError, "failed to update project members")
	}
}
