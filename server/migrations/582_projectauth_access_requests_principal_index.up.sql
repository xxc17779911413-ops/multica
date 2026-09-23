-- 2026-09-14 coder(lq): Support a requester's own status and cancellation view.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_requests_principal_idx
    ON projectauth_access_requests (workspace_id, requester_user_id, status, created_at, id);
