-- 2026-09-07 coder(lq): Add the subject lookup used when resolving a user's
-- effective project and task roles.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_grants_subject_idx
    ON projectauth_access_grants (subject_type, subject_id, workspace_id);
