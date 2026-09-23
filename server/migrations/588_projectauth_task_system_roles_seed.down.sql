DELETE FROM projectauth_task_role_permissions permissions
USING projectauth_task_roles roles
WHERE permissions.role_id = roles.id
  AND roles.is_system
  AND roles.role_key IN ('owner', 'manager', 'member', 'viewer');

DELETE FROM projectauth_task_roles
WHERE is_system
  AND role_key IN ('owner', 'manager', 'member', 'viewer');
