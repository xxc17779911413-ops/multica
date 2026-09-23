-- 2026-09-21 coder(lq): Let a project manager manage the project's access.
--
-- The seeded matrix gave project.member.manage to the owner alone, so a manager
-- could authorize work inside a task (project.issue.manage) but not manage who
-- may reach the project at all. The project access dialog was offered to them and
-- then reported that they had no permission to grant anything. Task-level and
-- project-level authorization now agree: whoever may manage the work may manage
-- its access.
--
-- Only the built-in manager role changes, and only by gaining the one permission
-- it lacked. A workspace that had deliberately removed something else from that
-- role keeps that decision; one that had removed this permission gets it back,
-- because a system role carries no marker distinguishing a default from an edit.
INSERT INTO project_permission_role_permissions (role_id, permission)
SELECT role.id, 'project.member.manage'
FROM project_permission_roles role
WHERE role.role_key = 'manager' AND role.is_system
ON CONFLICT DO NOTHING;
