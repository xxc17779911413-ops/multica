package projectauth

import "fmt"

var knownPermissions = map[Permission]struct{}{
	View: {}, Edit: {}, IssueCreate: {}, IssueComment: {}, IssueManage: {},
	IssueArchive: {}, AgentUse: {}, IssueChildCreate: {}, MemberManage: {}, SettingsManage: {},
}

var projectTaskPermissionProjection = map[Permission]Permission{
	View: View, Edit: Edit, IssueComment: IssueComment, IssueManage: IssueManage,
	IssueArchive: IssueArchive, AgentUse: AgentUse, IssueChildCreate: IssueChildCreate,
}

// ProjectPermissionToTask is the sole project-to-task projection. Project
// roles are never interpreted by the task role matrix; their resulting
// project permissions pass through this explicit map instead.
func ProjectPermissionToTask(permission Permission) (Permission, bool) {
	projected, ok := projectTaskPermissionProjection[permission]
	return projected, ok
}

// ProjectPermissionsToTask applies the complete inheritance boundary in one
// place: validate the project catalog, project task-safe permissions, then
// apply task implications/capping. Callers must not interpret a ProjectRole
// directly with the task role matrix.
func ProjectPermissionsToTask(permissions []Permission) ([]Permission, error) {
	projected := make([]Permission, 0, len(permissions))
	for _, permission := range permissions {
		if !IsKnownPermission(permission) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidIssuePermission, permission)
		}
		if taskPermission, ok := ProjectPermissionToTask(permission); ok {
			projected = append(projected, taskPermission)
		}
	}
	return TaskPermissionCap(projected)
}

func IsKnownPermission(permission Permission) bool {
	_, ok := knownPermissions[permission]
	return ok
}

func IsTaskPermission(permission Permission) bool {
	_, ok := projectTaskPermissionProjection[permission]
	return ok
}

// TaskPermissionCap filters known project-only permissions and fails closed
// for unknown values. This cap does not suppress project inheritance: callers
// first project project permissions, then merge the resulting task set.
func TaskPermissionCap(permissions []Permission) ([]Permission, error) {
	result := make([]Permission, 0, len(permissions))
	seen := make(map[Permission]struct{}, len(permissions))
	hasTaskPermission := false
	for _, permission := range permissions {
		if !IsKnownPermission(permission) {
			return nil, fmt.Errorf("%w: %s", ErrInvalidIssuePermission, permission)
		}
		if !IsTaskPermission(permission) {
			continue
		}
		hasTaskPermission = true
		if _, ok := seen[permission]; ok {
			continue
		}
		seen[permission] = struct{}{}
		result = append(result, permission)
	}
	if hasTaskPermission {
		if _, ok := seen[View]; !ok {
			result = append(result, View)
		}
	}
	return result, nil
}

func allTaskPermissions() []Permission {
	return []Permission{View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate}
}
