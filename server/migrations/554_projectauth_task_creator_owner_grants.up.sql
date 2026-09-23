-- 2026-09-07 coder(lq): The squash merge retained later authorization
-- migrations but dropped their earlier table-creation migrations because
-- those numbers collided with private migrations already on main. Create the
-- canonical tables idempotently here before applying the grant backfills.
CREATE TABLE IF NOT EXISTS projectauth_access_grants (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    project_id UUID NOT NULL,
    issue_id UUID,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('user', 'role', 'organization', 'everyone')),
    subject_id TEXT NOT NULL DEFAULT '',
    role_key TEXT,
    permission TEXT,
    source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'organization', 'everyone', 'migration', 'system')),
    granted_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((role_key IS NULL) <> (permission IS NULL))
);

CREATE TABLE IF NOT EXISTS projectauth_organizations (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    parent_id UUID,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projectauth_organization_members (
    organization_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    user_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2026-09-04 coder(lq): Backfill the task-scoped Owner grant for creators of
-- existing project-bound tasks. Runtime issue hooks cover new and updated
-- tasks; this migration keeps historical tasks visible after workspace-owner
-- bypass is disabled.
INSERT INTO projectauth_access_grants
    (workspace_id, project_id, issue_id, subject_type, subject_id,
     role_key, permission, source, granted_by)
SELECT i.workspace_id, i.project_id, i.id, 'user', i.creator_id::text,
       'owner', NULL, 'migration', NULL
FROM issue i
JOIN member m
  ON m.workspace_id = i.workspace_id
 AND m.user_id = i.creator_id
WHERE i.project_id IS NOT NULL
  AND i.creator_type = 'member'
ON CONFLICT DO NOTHING;

-- 2026-09-04 coder(lq): Agent-created tasks grant Owner to the owning human,
-- matching the runtime adapter and keeping external Agent identities out of
-- the authorization subject column.
INSERT INTO projectauth_access_grants
    (workspace_id, project_id, issue_id, subject_type, subject_id,
     role_key, permission, source, granted_by)
SELECT i.workspace_id, i.project_id, i.id, 'user', a.owner_id::text,
       'owner', NULL, 'migration', NULL
FROM issue i
JOIN agent a
  ON a.id = i.creator_id
 AND a.workspace_id = i.workspace_id
 AND a.kind = 'user'
JOIN member m
  ON m.workspace_id = i.workspace_id
 AND m.user_id = a.owner_id
WHERE i.project_id IS NOT NULL
  AND i.creator_type = 'agent'
  AND a.owner_id IS NOT NULL
ON CONFLICT DO NOTHING;
