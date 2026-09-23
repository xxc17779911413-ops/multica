-- 2026-09-14 coder(lq): A state transition produces at most one notification
-- for a recipient, even when an HTTP request or queue delivery is retried.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_request_notifications_delivery_uidx
    ON projectauth_access_request_notifications (workspace_id, request_id, recipient_user_id, event);
