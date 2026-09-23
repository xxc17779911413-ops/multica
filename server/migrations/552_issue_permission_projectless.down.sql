-- 2026-09-05 coder(lq): Restore the historical constraint only when no
-- projectless grants remain; never silently delete task-member permissions.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM issue_permissions WHERE project_id IS NULL) THEN
        RAISE EXCEPTION 'cannot restore issue_permissions.project_id NOT NULL while projectless grants exist';
    END IF;
    ALTER TABLE issue_permissions
        ALTER COLUMN project_id SET NOT NULL;
END $$;
