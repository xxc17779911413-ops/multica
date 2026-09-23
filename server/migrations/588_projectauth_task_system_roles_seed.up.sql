-- 2026-09-14 coder(lq): Seed the documented task matrix independently from
-- project_permission_roles. Re-running is idempotent through unique indexes.
WITH system_roles(role_key, name) AS (
    VALUES ('owner', 'Owner'), ('manager', 'Manager'), ('member', 'Member'), ('viewer', 'Viewer')
)
INSERT INTO projectauth_task_roles (workspace_id, role_key, name, is_system)
SELECT w.id, roles.role_key, roles.name, true
FROM workspace w
CROSS JOIN system_roles roles
ON CONFLICT (workspace_id, role_key) DO UPDATE
SET name = EXCLUDED.name,
    is_system = true,
    updated_at = now();

INSERT INTO projectauth_task_role_permissions (role_id, permission)
SELECT roles.id, matrix.permission
FROM projectauth_task_roles roles
JOIN (VALUES
    ('owner', 'project.view'),
    ('owner', 'project.edit'),
    ('owner', 'project.issue.comment'),
    ('owner', 'project.issue.manage'),
    ('owner', 'project.issue.archive'),
    ('owner', 'project.agent.use'),
    ('owner', 'project.issue.child.create'),
    ('manager', 'project.view'),
    ('manager', 'project.edit'),
    ('manager', 'project.issue.comment'),
    ('manager', 'project.issue.manage'),
    ('manager', 'project.issue.archive'),
    ('manager', 'project.agent.use'),
    ('manager', 'project.issue.child.create'),
    ('member', 'project.view'),
    ('member', 'project.edit'),
    ('member', 'project.issue.comment'),
    ('member', 'project.issue.child.create'),
    ('viewer', 'project.view')
) AS matrix(role_key, permission)
    ON matrix.role_key = roles.role_key
WHERE roles.is_system
ON CONFLICT (role_id, permission) DO NOTHING;
