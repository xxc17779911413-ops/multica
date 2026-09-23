-- 2026-09-07 coder(lq): Add the workspace/user lookup used by directory
-- membership and authorization resolution.
CREATE INDEX CONCURRENTLY IF NOT EXISTS projectauth_organization_members_user_idx
    ON projectauth_organization_members (workspace_id, user_id);
