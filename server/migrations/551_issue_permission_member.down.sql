-- 2026-09-05 coder(lq): Remove only the task-comment grant introduced here;
-- project.view already belongs to the preceding 440 migration contract.
DELETE FROM issue_permissions WHERE permission = 'project.issue.comment';
ALTER TABLE issue_permissions DROP CONSTRAINT IF EXISTS issue_permissions_permission_check;
ALTER TABLE issue_permissions ADD CONSTRAINT issue_permissions_permission_check
    CHECK (permission IN ('project.view', 'project.edit', 'project.issue.manage', 'project.agent.use'));
