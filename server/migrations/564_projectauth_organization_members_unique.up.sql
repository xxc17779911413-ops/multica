-- 2026-09-07 coder(lq): Keep organization membership imports idempotent.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_organization_members_pkey
    ON projectauth_organization_members (organization_id, user_id);
