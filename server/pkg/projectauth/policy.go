package projectauth

// 2026-08-27 coder(lq): Map project roles to permissions. Service.Check keeps
// native workspace-owner semantics and excludes membership management from
// the otherwise-preserved workspace-admin bypass.
type Policy struct {
	roles map[ProjectRole]map[Permission]bool
}

var systemRoleNames = map[ProjectRole]string{
	ProjectOwner:   "Owner",
	ProjectManager: "Manager",
	ProjectMember:  "Member",
	ProjectViewer:  "Viewer",
}

func SystemRoleDefinitions() []RoleDefinition {
	policy := DefaultPolicy()
	roles := make([]RoleDefinition, 0, len(systemRoleNames))
	for _, role := range []ProjectRole{ProjectOwner, ProjectManager, ProjectMember, ProjectViewer} {
		permissions := make([]Permission, 0)
		for permission, allowed := range policy.roles[role] {
			if allowed {
				permissions = append(permissions, permission)
			}
		}
		roles = append(roles, RoleDefinition{Key: role, Name: systemRoleNames[role], Scope: RoleScopeProject, IsSystem: true, Permissions: permissions})
	}
	return roles
}

func DefaultPolicy() Policy {
	return Policy{roles: map[ProjectRole]map[Permission]bool{
		ProjectOwner: {
			View: true, Edit: true, IssueCreate: true, IssueComment: true, IssueManage: true,
			IssueArchive: true, AgentUse: true, MemberManage: true, SettingsManage: true,
		},
		// 2026-09-21 coder(lq): A manager may manage the project's access, so
		// task-level and project-level authorization agree: whoever may manage the
		// work may manage who reaches it.
		ProjectManager: {
			View: true, Edit: true, IssueCreate: true, IssueComment: true, IssueManage: true,
			IssueArchive: true, AgentUse: true, MemberManage: true,
		},
		// 2026-09-03 coder(lq): Project members may archive tasks, while the
		// separate issue-management permission remains reserved for managers.
		ProjectMember: {View: true, IssueCreate: true, IssueComment: true, IssueArchive: true, AgentUse: true},
		ProjectViewer: {View: true},
	}}
}

func (p Policy) Allows(role ProjectRole, permission Permission) bool {
	return p.roles[role][permission]
}

func validProjectRole(role ProjectRole) bool {
	switch role {
	case ProjectOwner, ProjectManager, ProjectMember, ProjectViewer:
		return true
	default:
		return false
	}
}

func IsSystemRole(role ProjectRole) bool { return validProjectRole(role) }
