-- 2026-09-14 coder(lq): A grant has at most one active constraint record.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_grant_constraints_workspace_grant_uidx
    ON projectauth_grant_constraints (workspace_id, grant_id);
