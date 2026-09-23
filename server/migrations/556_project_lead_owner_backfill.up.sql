-- 2026-08-27 coder(lq): Backfill project owners for existing projects whose
-- member lead was created before the project authorization overlay existed.
-- This only promotes the lead; it never downgrades an existing role.
INSERT INTO project_members (project_id, user_id, role)
SELECT p.id, p.lead_id, 'owner'
FROM project p
JOIN member m
  ON m.workspace_id = p.workspace_id
 AND m.user_id = p.lead_id
WHERE p.lead_type = 'member'
  AND p.lead_id IS NOT NULL
ON CONFLICT (project_id, user_id)
DO UPDATE SET
  role = 'owner',
  updated_at = now()
WHERE project_members.role <> 'owner';
