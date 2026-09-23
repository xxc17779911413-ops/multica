-- 2026-09-14 coder(lq): Task role keys are workspace-scoped.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_task_roles_workspace_key_uidx
    ON projectauth_task_roles (workspace_id, role_key);
