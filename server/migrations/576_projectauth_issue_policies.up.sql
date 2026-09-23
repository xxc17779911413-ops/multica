-- 2026-09-14 coder(lq): Keep task visibility policy in a private extension
-- table so upstream issue schema updates remain conflict-free.
CREATE TABLE IF NOT EXISTS projectauth_issue_policies (
    workspace_id UUID NOT NULL,
    issue_id UUID NOT NULL,
    project_access_mode TEXT NOT NULL DEFAULT 'inherit'
        CHECK (project_access_mode IN ('inherit', 'restricted')),
    policy_version BIGINT NOT NULL DEFAULT 1 CHECK (policy_version > 0),
    created_by UUID,
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
