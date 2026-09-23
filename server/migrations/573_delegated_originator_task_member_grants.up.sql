-- 2026-09-09 coder(lq): Historical Agent-created tasks could notify the
-- delegating human without granting that human task visibility. Backfill the
-- task-scoped Member grant using the same direct-human lineage rule as the
-- delegated subscriber path; do not grant project-wide membership.
WITH RECURSIVE lineage AS (
    SELECT i.id AS issue_id,
           i.workspace_id,
           i.project_id,
           atq.originator_user_id AS delegated_user_id,
           atq.originator_source,
           atq.delegated_from_task_id,
           0 AS depth
    FROM issue i
    JOIN agent creator_agent
      ON creator_agent.id = i.creator_id
     AND creator_agent.workspace_id = i.workspace_id
    JOIN agent_task_queue atq
      ON atq.id = i.origin_id
    JOIN agent origin_agent
      ON origin_agent.id = atq.agent_id
     AND origin_agent.workspace_id = i.workspace_id
    WHERE i.creator_type = 'agent'
      AND i.origin_type IN ('quick_create', 'agent_create')
      AND atq.originator_user_id IS NOT NULL

    UNION ALL

    SELECT child.issue_id,
           child.workspace_id,
           child.project_id,
           child.delegated_user_id,
           parent.originator_source,
           parent.delegated_from_task_id,
           child.depth + 1
    FROM lineage child
    JOIN agent_task_queue parent
      ON parent.id = child.delegated_from_task_id
    JOIN agent parent_agent
      ON parent_agent.id = parent.agent_id
     AND parent_agent.workspace_id = child.workspace_id
    WHERE child.originator_source IN ('delegation', 'comment_source')
      AND child.depth < 32
),
chain_roots AS (
    SELECT DISTINCT ON (issue_id)
           issue_id,
           workspace_id,
           project_id,
           delegated_user_id,
           originator_source AS root_source
    FROM lineage
    ORDER BY issue_id, depth DESC
),
eligible AS (
    SELECT root.issue_id,
           root.workspace_id,
           root.project_id,
           root.delegated_user_id
    FROM chain_roots root
    JOIN member m
      ON m.workspace_id = root.workspace_id
     AND m.user_id = root.delegated_user_id
    WHERE root.root_source = 'direct_human'
),
project_bound AS (
    INSERT INTO projectauth_access_grants
        (workspace_id, project_id, issue_id, subject_type, subject_id,
         role_key, permission, source, granted_by)
    SELECT workspace_id, project_id, issue_id, 'user', delegated_user_id::text,
           'member', NULL, 'migration', NULL
    FROM eligible
    WHERE project_id IS NOT NULL
      AND NOT EXISTS (
          SELECT 1
          FROM projectauth_access_grants existing
          WHERE existing.project_id = eligible.project_id
            AND existing.issue_id = eligible.issue_id
            AND existing.subject_type = 'user'
            AND existing.subject_id = eligible.delegated_user_id::text
            AND existing.role_key IN ('owner', 'manager', 'member')
            AND existing.permission IS NULL
      )
    ON CONFLICT DO NOTHING
    RETURNING id
)
INSERT INTO projectauth_issue_access_grants
    (workspace_id, issue_id, subject_type, subject_id,
     role_key, source, granted_by)
SELECT workspace_id, issue_id, 'user', delegated_user_id::text,
       'member', 'migration', NULL
FROM eligible
WHERE project_id IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM projectauth_issue_access_grants existing
      WHERE existing.workspace_id = eligible.workspace_id
        AND existing.issue_id = eligible.issue_id
        AND existing.subject_type = 'user'
        AND existing.subject_id = eligible.delegated_user_id::text
        AND existing.role_key IN ('owner', 'manager', 'member')
  )
ON CONFLICT DO NOTHING;
