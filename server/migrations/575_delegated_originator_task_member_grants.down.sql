-- 2026-09-09 coder(lq): Roll back only the migration-sourced task Member
-- grants that still match the delegated direct-human lineage. Runtime system
-- grants and every project-level or manually shared permission remain intact.
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
    DELETE FROM projectauth_access_grants grant_row
    USING eligible
    WHERE grant_row.workspace_id = eligible.workspace_id
      AND grant_row.project_id = eligible.project_id
      AND grant_row.issue_id = eligible.issue_id
      AND grant_row.subject_type = 'user'
      AND grant_row.subject_id = eligible.delegated_user_id::text
      AND grant_row.role_key = 'member'
      AND grant_row.permission IS NULL
      AND grant_row.source = 'migration'
    RETURNING grant_row.id
)
DELETE FROM projectauth_issue_access_grants grant_row
USING eligible
WHERE grant_row.workspace_id = eligible.workspace_id
  AND grant_row.issue_id = eligible.issue_id
  AND grant_row.subject_type = 'user'
  AND grant_row.subject_id = eligible.delegated_user_id::text
  AND grant_row.role_key = 'member'
  AND grant_row.source = 'migration';
