-- 2026-09-04 coder(lq): Remove only the task-creator rows introduced by this
-- migration; runtime system grants and manual grants remain untouched.
DELETE FROM projectauth_access_grants g
WHERE g.source = 'migration'
  AND g.issue_id IS NOT NULL
  AND g.role_key = 'owner'
  AND g.permission IS NULL
  AND EXISTS (
      SELECT 1
      FROM issue i
      LEFT JOIN agent a
        ON a.id = i.creator_id
       AND a.workspace_id = i.workspace_id
       AND a.kind = 'user'
      WHERE i.id = g.issue_id
        AND i.project_id = g.project_id
        AND i.workspace_id = g.workspace_id
        AND (
            (i.creator_type = 'member' AND g.subject_type = 'user'
             AND g.subject_id = i.creator_id::text)
            OR
            (i.creator_type = 'agent' AND g.subject_type = 'user'
             AND g.subject_id = a.owner_id::text)
        )
  );
