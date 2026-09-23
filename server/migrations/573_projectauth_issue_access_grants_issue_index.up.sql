-- 2026-09-07 coder(lq): Add the workspace/task lookup used by task-scoped
-- authorization checks.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_issue_access_grants_issue_idx
    ON projectauth_issue_access_grants (workspace_id, issue_id);
