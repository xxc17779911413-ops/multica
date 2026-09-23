-- 2026-09-07 coder(lq): Add the subject lookup used when resolving a user's
-- effective projectless task roles.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_issue_access_grants_subject_idx
    ON projectauth_issue_access_grants (workspace_id, subject_type, subject_id);
