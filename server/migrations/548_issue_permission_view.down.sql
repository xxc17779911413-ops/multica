DELETE FROM issue_permissions WHERE permission = 'project.view';
ALTER TABLE issue_permissions DROP CONSTRAINT IF EXISTS issue_permissions_permission_check;
ALTER TABLE issue_permissions ADD CONSTRAINT issue_permissions_permission_check
    CHECK (permission IN ('project.edit', 'project.issue.manage', 'project.agent.use'));
