DROP TRIGGER IF EXISTS trg_agent_daily_stats_for_queue ON agent_task_queue;
DROP FUNCTION IF EXISTS maintain_agent_daily_stats_for_queue();
DROP FUNCTION IF EXISTS agent_daily_stats_apply(UUID, UUID, DATE, BIGINT, BIGINT, BIGINT);
DROP INDEX IF EXISTS idx_agent_daily_stats_workspace_date_agent;
DROP TABLE IF EXISTS agent_daily_stats;
