-- 2026-09-14 coder(lq): Support task-owner pending approval queues.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_requests_pending_resource_idx
    ON projectauth_access_requests (workspace_id, issue_id, created_at, id)
    WHERE status = 'pending';
