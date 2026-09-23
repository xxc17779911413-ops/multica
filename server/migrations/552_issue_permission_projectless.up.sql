-- 2026-09-05 coder(lq): Task-level MEMBER grants also cover projectless
-- issues. A nullable project_id keeps those grants scoped to issue_id without
-- creating a project membership row.
ALTER TABLE issue_permissions
    ALTER COLUMN project_id DROP NOT NULL;
