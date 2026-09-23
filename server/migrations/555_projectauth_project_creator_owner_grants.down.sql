-- 2026-09-04 coder(lq): Remove only creator-owner grants that this backfill
-- could have introduced. A legacy project_members owner means migration 453
-- supplied the canonical grant, so leave that row intact during rollback.
DELETE FROM projectauth_access_grants g
WHERE g.source = 'migration'
  AND g.issue_id IS NULL
  AND g.subject_type = 'user'
  AND g.role_key = 'owner'
  AND g.permission IS NULL
  AND EXISTS (
      SELECT 1
      FROM project p
      JOIN member m
        ON m.workspace_id = p.workspace_id
       AND m.user_id = p.created_by
      WHERE p.id = g.project_id
        AND p.workspace_id = g.workspace_id
        AND p.created_by IS NOT NULL
        AND g.subject_id = p.created_by::text
  )
  AND NOT EXISTS (
      SELECT 1
      FROM project_members pm
      WHERE pm.project_id = g.project_id
        AND pm.user_id::text = g.subject_id
        AND pm.role = 'owner'
  );
