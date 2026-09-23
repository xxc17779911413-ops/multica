-- 2026-08-28 coder(lq): Store workspace-scoped system-role overrides and custom
-- roles outside Multica's native member tables so upstream upgrades stay low
-- conflict and permission changes take effect on the next request.
CREATE TABLE project_permission_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    role_key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_by UUID REFERENCES "user"(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, role_key)
);

CREATE TABLE project_permission_role_permissions (
    role_id UUID NOT NULL REFERENCES project_permission_roles(id) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role_id, permission)
);

ALTER TABLE project_members
    DROP CONSTRAINT IF EXISTS project_members_role_check,
    ADD COLUMN custom_role_id UUID REFERENCES project_permission_roles(id) ON DELETE SET NULL;

CREATE INDEX project_permission_roles_workspace_idx ON project_permission_roles (workspace_id);
CREATE INDEX project_members_custom_role_idx ON project_members (custom_role_id);

-- Seed every workspace with the four built-in roles. They are ordinary rows
-- for permission resolution; is_system only prevents deletion in the API.
WITH system_roles(role_key, name) AS (
    VALUES ('owner', 'Owner'), ('manager', 'Manager'), ('member', 'Member'), ('viewer', 'Viewer')
)
INSERT INTO project_permission_roles (workspace_id, role_key, name, is_system)
SELECT w.id, s.role_key, s.name, true
FROM workspace w CROSS JOIN system_roles s
ON CONFLICT (workspace_id, role_key) DO NOTHING;

INSERT INTO project_permission_role_permissions (role_id, permission)
SELECT r.id, p.permission
FROM project_permission_roles r
JOIN (VALUES
    ('owner','project.view'), ('owner','project.edit'), ('owner','project.issue.create'),
    ('owner','project.issue.manage'), ('owner','project.agent.use'), ('owner','project.member.manage'),
    ('owner','project.settings.manage'), ('manager','project.view'), ('manager','project.edit'),
    ('manager','project.issue.create'), ('manager','project.issue.manage'), ('manager','project.agent.use'),
    ('member','project.view'), ('member','project.issue.create'), ('member','project.agent.use'),
    ('viewer','project.view')
) AS p(role_key, permission) ON p.role_key = r.role_key
ON CONFLICT DO NOTHING;
