-- 2026-09-03 coder(lq): Roll back only the built-in archive permission.
DELETE FROM project_permission_role_permissions permissions
USING project_permission_roles role_def
WHERE permissions.role_id = role_def.id
  AND permissions.permission = 'project.issue.archive'
  AND role_def.is_system
  AND role_def.role_key IN ('owner', 'manager', 'member');
