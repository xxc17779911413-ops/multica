DROP INDEX IF EXISTS issue_workspace_archived_position_idx;
ALTER TABLE issue DROP COLUMN IF EXISTS archived_at;
