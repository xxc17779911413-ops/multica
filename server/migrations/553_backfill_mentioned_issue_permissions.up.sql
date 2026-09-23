-- 2026-09-05 coder(lq): Make the task-member rule the single source of truth
-- for historical @mentions. Inbox rows are notifications, not permissions.
WITH mentioned_member AS (
    SELECT s.issue_id, s.user_id
    FROM issue_subscriber s
    WHERE s.user_type = 'member'
      AND s.reason = 'mentioned'
    UNION
    SELECT i.issue_id, i.recipient_id
    FROM inbox_item i
    WHERE i.recipient_type = 'member'
      AND i.type = 'mentioned'
      AND i.issue_id IS NOT NULL
)
INSERT INTO issue_permissions (issue_id, project_id, user_id, permission, granted_by)
SELECT mm.issue_id,
       i.project_id,
       mm.user_id,
       p.permission,
       mm.user_id
FROM mentioned_member mm
JOIN issue i ON i.id = mm.issue_id
JOIN member m ON m.workspace_id = i.workspace_id AND m.user_id = mm.user_id
CROSS JOIN (VALUES ('project.view'), ('project.issue.comment')) AS p(permission)
ON CONFLICT (issue_id, user_id, permission) DO NOTHING;
