-- 2026-09-14 coder(lq): Keep one row per task role permission.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_task_role_permissions_role_permission_uidx
    ON projectauth_task_role_permissions (role_id, permission);
