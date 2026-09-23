DELETE FROM project_permission_role_permissions permission
USING project_permission_roles role
WHERE permission.role_id = role.id
  AND permission.permission = 'project.member.manage'
  AND role.role_key = 'manager'
  AND role.is_system;
