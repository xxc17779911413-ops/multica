-- 2026-09-07 coder(lq): Add the workspace-scoped lookup used by project and
-- task authorization checks.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_grants_workspace_project_idx
    ON projectauth_access_grants (workspace_id, project_id, issue_id);
