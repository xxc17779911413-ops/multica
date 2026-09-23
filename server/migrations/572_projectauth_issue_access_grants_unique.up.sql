-- 2026-09-07 coder(lq): Recreate the idempotency key for projectless task
-- grants as a standalone concurrent index.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_issue_access_grants_uniq
    ON projectauth_issue_access_grants (workspace_id, issue_id, subject_type, subject_id, role_key, source);
