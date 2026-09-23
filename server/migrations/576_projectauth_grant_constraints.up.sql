-- 2026-09-14 coder(lq): Add expiry and provenance beside the existing grant
-- table without coupling its lifecycle to upstream resources through FKs.
CREATE TABLE IF NOT EXISTS projectauth_grant_constraints (
    workspace_id UUID NOT NULL,
    grant_id UUID NOT NULL,
    expires_at TIMESTAMPTZ,
    origin_kind TEXT NOT NULL DEFAULT 'manual'
        CHECK (origin_kind IN ('manual', 'access_request', 'system')),
    origin_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
