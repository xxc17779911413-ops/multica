-- 2026-08-28 coder(lq): Allow additive task-scoped visibility grants.
ALTER TABLE issue_permissions DROP CONSTRAINT IF EXISTS issue_permissions_permission_check;
ALTER TABLE issue_permissions ADD CONSTRAINT issue_permissions_permission_check
    CHECK (permission IN ('project.view', 'project.edit', 'project.issue.manage', 'project.agent.use'));
