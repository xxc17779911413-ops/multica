-- 2026-09-07 coder(lq): Keep task-grant inserts idempotent for project-bound
-- issues while preserving the separate projectless grant table.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_grants_issue_uniq
    ON projectauth_access_grants (project_id, issue_id, subject_type, subject_id, COALESCE(role_key, ''), COALESCE(permission, ''))
    WHERE issue_id IS NOT NULL;
