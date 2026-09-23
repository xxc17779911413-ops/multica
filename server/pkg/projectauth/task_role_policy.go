package projectauth

// TaskPolicy owns the task role matrix. It must never reuse Policy because
// same-named project and task roles deliberately have different permissions.
// 2026-09-14 coder(lq): Establish the independent task authorization catalog.
type TaskPolicy struct {
	roles map[TaskRole]map[Permission]bool
}

type TaskRoleDefinition struct {
	ID          string       `json:"id"`
	WorkspaceID string       `json:"workspace_id"`
	Key         TaskRole     `json:"key"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Scope       RoleScope    `json:"scope"`
	IsSystem    bool         `json:"is_system"`
	Permissions []Permission `json:"permissions"`
}

var taskSystemRoleNames = map[TaskRole]string{
	TaskOwner:   "Owner",
	TaskManager: "Manager",
	TaskMember:  "Member",
	TaskViewer:  "Viewer",
}

func TaskPermissionSet() []Permission {
	return []Permission{View, Edit, IssueComment, IssueManage, IssueArchive, AgentUse, IssueChildCreate}
}

func DefaultTaskPolicy() TaskPolicy {
	ownerAndManager := map[Permission]bool{
		View: true, Edit: true, IssueComment: true, IssueManage: true,
		IssueArchive: true, AgentUse: true, IssueChildCreate: true,
	}
	return TaskPolicy{roles: map[TaskRole]map[Permission]bool{
		TaskOwner:   clonePermissionMap(ownerAndManager),
		TaskManager: clonePermissionMap(ownerAndManager),
		TaskMember:  {View: true, Edit: true, IssueComment: true, IssueChildCreate: true},
		TaskViewer:  {View: true},
	}}
}

func (p TaskPolicy) Allows(role TaskRole, permission Permission) bool {
	return p.roles[role][permission]
}

func TaskSystemRoleDefinitions() []TaskRoleDefinition {
	policy := DefaultTaskPolicy()
	definitions := make([]TaskRoleDefinition, 0, len(taskSystemRoleNames))
	for _, role := range []TaskRole{TaskOwner, TaskManager, TaskMember, TaskViewer} {
		permissions := make([]Permission, 0)
		for _, permission := range TaskPermissionSet() {
			if policy.Allows(role, permission) {
				permissions = append(permissions, permission)
			}
		}
		definitions = append(definitions, TaskRoleDefinition{
			Key: role, Name: taskSystemRoleNames[role], Scope: RoleScopeTask,
			IsSystem: true, Permissions: permissions,
		})
	}
	return definitions
}

func IsSystemTaskRole(role TaskRole) bool {
	switch role {
	case TaskOwner, TaskManager, TaskMember, TaskViewer:
		return true
	default:
		return false
	}
}

func clonePermissionMap(source map[Permission]bool) map[Permission]bool {
	result := make(map[Permission]bool, len(source))
	for permission, allowed := range source {
		result[permission] = allowed
	}
	return result
}
