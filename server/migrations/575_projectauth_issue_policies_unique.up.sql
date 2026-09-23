-- 2026-09-14 coder(lq): One optimistic-lock policy row per task.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_issue_policies_workspace_issue_uidx
    ON projectauth_issue_policies (workspace_id, issue_id);
