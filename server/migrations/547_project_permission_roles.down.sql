-- 2026-08-28 coder(lq): Roll back the independent project role catalog.
ALTER TABLE project_members DROP COLUMN IF EXISTS custom_role_id;
DROP TABLE IF EXISTS project_permission_role_permissions;
DROP TABLE IF EXISTS project_permission_roles;
