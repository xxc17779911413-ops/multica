-- 2026-09-14 coder(lq): One live request per requester/task/role. Expired and
-- otherwise terminal requests remain as immutable audit history.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_requests_pending_subject_role_uidx
    ON projectauth_access_requests (workspace_id, issue_id, requester_user_id, requested_role_key)
    WHERE status = 'pending';
