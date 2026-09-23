DROP INDEX IF EXISTS idx_project_created_by;
ALTER TABLE project DROP COLUMN IF EXISTS created_by;
