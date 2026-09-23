package handler

import (
	"net/http"

	"github.com/multica-ai/multica/server/pkg/projectauth"
)

type taskPermissionRoleResponse struct {
	ID          string                   `json:"id"`
	WorkspaceID string                   `json:"workspace_id"`
	Key         string                   `json:"key"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	IsSystem    bool                     `json:"is_system"`
	Scope       projectauth.RoleScope    `json:"scope"`
	Permissions []projectauth.Permission `json:"permissions"`
}

// ListTaskPermissionRoles exposes the independent task-role catalog. It must
// never delegate to the project-role service: equal role keys intentionally
// have separate matrices in the two scopes.
func (h *Handler) ListTaskPermissionRoles(w http.ResponseWriter, r *http.Request) {
	subject, ok := h.projectPermissionRoleSubject(w, r)
	if !ok {
		return
	}
	repository := &projectAuthRepository{db: h.DB}
	if err := repository.ensureTaskSystemRoleDefinitions(r.Context(), subject.WorkspaceID); err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	rows, err := h.DB.Query(r.Context(), `
		SELECT role.id::text, role.workspace_id::text, role.role_key, role.name,
		       role.description, role.is_system, permission.permission
		FROM projectauth_task_roles role
		LEFT JOIN projectauth_task_role_permissions permission ON permission.role_id=role.id
		WHERE role.workspace_id=$1
		ORDER BY role.is_system DESC, role.name, role.role_key, permission.permission`, subject.WorkspaceID)
	if err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	defer rows.Close()
	roles := make([]taskPermissionRoleResponse, 0)
	byID := map[string]int{}
	for rows.Next() {
		var role taskPermissionRoleResponse
		var permission *projectauth.Permission
		if err := rows.Scan(&role.ID, &role.WorkspaceID, &role.Key, &role.Name, &role.Description, &role.IsSystem, &permission); err != nil {
			writeProjectPermissionRoleError(w, err)
			return
		}
		index, found := byID[role.ID]
		if !found {
			role.Scope = projectauth.RoleScopeTask
			role.Permissions = []projectauth.Permission{}
			roles = append(roles, role)
			index = len(roles) - 1
			byID[role.ID] = index
		}
		if permission != nil {
			roles[index].Permissions = append(roles[index].Permissions, *permission)
		}
	}
	if err := rows.Err(); err != nil {
		writeProjectPermissionRoleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scope": projectauth.RoleScopeTask, "roles": roles})
}
