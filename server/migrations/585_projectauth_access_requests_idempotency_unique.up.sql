-- 2026-09-14 coder(lq): Make repeated client submissions return one request.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_requests_workspace_idempotency_uidx
    ON projectauth_access_requests (workspace_id, idempotency_key);
