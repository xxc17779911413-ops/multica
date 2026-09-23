-- 2026-09-07 coder(lq): Remove stale authorization and directory rows while
-- keeping relationship integrity in the application layer. Database foreign
-- keys are intentionally avoided so workspace teardown remains explicit and
-- compatible with the repository's migration policy.
DELETE FROM projectauth_access_grants g
WHERE NOT EXISTS (
    SELECT 1 FROM project p
    WHERE p.id = g.project_id AND p.workspace_id = g.workspace_id
)
   OR (
       g.issue_id IS NOT NULL
       AND NOT EXISTS (
           SELECT 1 FROM issue i
           WHERE i.id = g.issue_id
             AND i.project_id = g.project_id
             AND i.workspace_id = g.workspace_id
       )
   );

UPDATE projectauth_organizations o
SET parent_id = NULL
WHERE parent_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM projectauth_organizations parent
      WHERE parent.id = o.parent_id AND parent.workspace_id = o.workspace_id
  );

DELETE FROM projectauth_organization_members om
WHERE NOT EXISTS (
    SELECT 1 FROM projectauth_organizations o
    WHERE o.id = om.organization_id AND o.workspace_id = om.workspace_id
)
   OR NOT EXISTS (
       SELECT 1 FROM member m
       WHERE m.workspace_id = om.workspace_id AND m.user_id = om.user_id
   );
