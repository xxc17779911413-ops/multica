-- 2026-09-14 coder(lq): Persist task roles separately from project roles so
-- same-named roles can evolve without cross-scope privilege changes.
CREATE TABLE IF NOT EXISTS projectauth_task_roles (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    role_key TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(btrim(role_key)) > 0),
    CHECK (length(btrim(name)) > 0)
);
