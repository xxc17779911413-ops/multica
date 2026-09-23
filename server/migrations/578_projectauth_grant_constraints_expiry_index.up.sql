-- 2026-09-14 coder(lq): Support effective-grant filtering and expiry jobs.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_grant_constraints_workspace_expiry_idx
    ON projectauth_grant_constraints (workspace_id, expires_at, grant_id)
    WHERE expires_at IS NOT NULL;
