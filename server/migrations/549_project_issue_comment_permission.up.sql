-- 2026-09-02 coder(lq): Add a narrow task-conversation permission so project
-- members can comment without receiving project metadata edit access.
INSERT INTO project_permission_role_permissions (role_id, permission)
SELECT role_def.id, 'project.issue.comment'
FROM project_permission_roles role_def
WHERE role_def.is_system
  AND role_def.role_key IN ('owner', 'manager', 'member')
ON CONFLICT DO NOTHING;
