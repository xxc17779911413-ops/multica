-- 2026-09-03 coder(lq): Let project members archive tasks without granting
-- broader task-management permission. Keep this additive so custom roles and
-- existing per-role overrides remain unchanged.
INSERT INTO project_permission_role_permissions (role_id, permission)
SELECT role_def.id, 'project.issue.archive'
FROM project_permission_roles role_def
WHERE role_def.is_system
  AND role_def.role_key IN ('owner', 'manager', 'member')
ON CONFLICT DO NOTHING;
