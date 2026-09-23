-- 2026-09-04 coder(lq): Restore project visibility for projects created before
-- the project authorization overlay was enabled. New projects seed this grant
-- in the creation transaction; this idempotent backfill covers only historical
-- rows whose recorded creator is still an active member of the same workspace.
INSERT INTO projectauth_access_grants
    (workspace_id, project_id, issue_id, subject_type, subject_id,
     role_key, permission, source, granted_by)
SELECT p.workspace_id, p.id, NULL, 'user', p.created_by::text,
       'owner', NULL, 'migration', NULL
FROM project p
JOIN member m
  ON m.workspace_id = p.workspace_id
 AND m.user_id = p.created_by
WHERE p.created_by IS NOT NULL
ON CONFLICT DO NOTHING;
