-- 2026-09-14 coder(lq): Store the independent task permission matrix without
-- an FK; application transactions maintain role lifecycle integrity.
CREATE TABLE IF NOT EXISTS projectauth_task_role_permissions (
    role_id UUID NOT NULL,
    permission TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (permission IN (
        'project.view',
        'project.edit',
        'project.issue.comment',
        'project.issue.manage',
        'project.issue.archive',
        'project.agent.use',
        'project.issue.child.create'
    ))
);
