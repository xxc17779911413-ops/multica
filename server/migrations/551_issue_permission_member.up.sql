-- 2026-09-05 coder(lq): Mentioned users are members of one task, not of the
-- whole project. Store the two permissions needed to open and reply to it.
ALTER TABLE issue_permissions DROP CONSTRAINT IF EXISTS issue_permissions_permission_check;
ALTER TABLE issue_permissions ADD CONSTRAINT issue_permissions_permission_check
    CHECK (permission IN ('project.view', 'project.issue.comment', 'project.edit', 'project.issue.manage', 'project.agent.use'));
