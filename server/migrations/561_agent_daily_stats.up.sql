-- 2026-09-07 coder(lq): Keep the agent dashboards off the hot queue table.
-- The two API aggregates only need daily totals, so maintain a compact
-- workspace/agent/day summary as queue rows are written or changed.
BEGIN;

CREATE TABLE agent_daily_stats (
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agent(id) ON DELETE CASCADE,
    stat_date DATE NOT NULL,
    run_count BIGINT NOT NULL DEFAULT 0,
    task_count BIGINT NOT NULL DEFAULT 0,
    failed_count BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, agent_id, stat_date)
);

CREATE INDEX idx_agent_daily_stats_workspace_date_agent
    ON agent_daily_stats (workspace_id, stat_date, agent_id);

-- 2026-09-07 coder(lq): Apply deltas through one helper so INSERT/UPDATE/
-- DELETE paths use identical upsert and non-negative-counter semantics.
CREATE OR REPLACE FUNCTION agent_daily_stats_apply(
    p_workspace_id UUID,
    p_agent_id UUID,
    p_stat_date DATE,
    p_run_delta BIGINT,
    p_task_delta BIGINT,
    p_failed_delta BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_workspace_id IS NULL OR p_agent_id IS NULL OR p_stat_date IS NULL THEN
        RETURN;
    END IF;

    INSERT INTO agent_daily_stats (
        workspace_id, agent_id, stat_date,
        run_count, task_count, failed_count
    )
    VALUES (
        p_workspace_id, p_agent_id, p_stat_date,
        GREATEST(p_run_delta, 0),
        GREATEST(p_task_delta, 0),
        GREATEST(p_failed_delta, 0)
    )
    ON CONFLICT (workspace_id, agent_id, stat_date) DO UPDATE
    SET run_count = GREATEST(0, agent_daily_stats.run_count + EXCLUDED.run_count + LEAST(p_run_delta, 0)),
        task_count = GREATEST(0, agent_daily_stats.task_count + EXCLUDED.task_count + LEAST(p_task_delta, 0)),
        failed_count = GREATEST(0, agent_daily_stats.failed_count + EXCLUDED.failed_count + LEAST(p_failed_delta, 0));
END;
$$;

-- 2026-09-07 coder(lq): Queue rows can be inserted with a terminal state,
-- retried, failed, cancelled, reassigned, or deleted. Record both the run
-- day and completion day so every mutation keeps the summary convergent.
CREATE OR REPLACE FUNCTION maintain_agent_daily_stats_for_queue()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_workspace_id UUID;
    new_workspace_id UUID;
    old_run_date DATE;
    new_run_date DATE;
    old_completion_date DATE;
    new_completion_date DATE;
    old_task_delta BIGINT;
    new_task_delta BIGINT;
    old_failed_delta BIGINT;
    new_failed_delta BIGINT;
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE') THEN
        SELECT workspace_id INTO old_workspace_id FROM agent WHERE id = OLD.agent_id;
        old_run_date := (OLD.created_at AT TIME ZONE 'UTC')::date;
        old_completion_date := CASE
            WHEN OLD.completed_at IS NULL THEN NULL
            ELSE (OLD.completed_at AT TIME ZONE 'UTC')::date
        END;
        old_task_delta := CASE WHEN OLD.completed_at IS NULL THEN 0 ELSE 1 END;
        old_failed_delta := CASE WHEN OLD.completed_at IS NOT NULL AND OLD.status = 'failed' THEN 1 ELSE 0 END;

        PERFORM agent_daily_stats_apply(old_workspace_id, OLD.agent_id, old_run_date, -1, 0, 0);
        PERFORM agent_daily_stats_apply(old_workspace_id, OLD.agent_id, old_completion_date, 0, -old_task_delta, -old_failed_delta);
    END IF;

    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        SELECT workspace_id INTO new_workspace_id FROM agent WHERE id = NEW.agent_id;
        new_run_date := (NEW.created_at AT TIME ZONE 'UTC')::date;
        new_completion_date := CASE
            WHEN NEW.completed_at IS NULL THEN NULL
            ELSE (NEW.completed_at AT TIME ZONE 'UTC')::date
        END;
        new_task_delta := CASE WHEN NEW.completed_at IS NULL THEN 0 ELSE 1 END;
        new_failed_delta := CASE WHEN NEW.completed_at IS NOT NULL AND NEW.status = 'failed' THEN 1 ELSE 0 END;

        PERFORM agent_daily_stats_apply(new_workspace_id, NEW.agent_id, new_run_date, 1, 0, 0);
        PERFORM agent_daily_stats_apply(new_workspace_id, NEW.agent_id, new_completion_date, 0, new_task_delta, new_failed_delta);
        RETURN NEW;
    END IF;

    RETURN OLD;
END;
$$;

-- 2026-09-07 coder(lq): Install the trigger before the backfill so queue
-- writes that arrive while the historical scan is running are not missed.
-- The backfill uses overwrite semantics, so rows already seen by the trigger
-- converge to the same totals rather than being double-counted.
CREATE TRIGGER trg_agent_daily_stats_for_queue
AFTER INSERT OR UPDATE OF agent_id, created_at, completed_at, status OR DELETE
ON agent_task_queue
FOR EACH ROW EXECUTE FUNCTION maintain_agent_daily_stats_for_queue();

-- Backfill existing queue history. UTC is explicit so a connection/session
-- timezone cannot split one day into two buckets. Wrap the lock and snapshot
-- in the migration transaction so concurrent queue writes are blocked until
-- the summary is complete; a failed migration rolls all objects back.
LOCK TABLE agent_task_queue IN SHARE MODE;
WITH contributions AS (
    SELECT
        a.workspace_id,
        atq.agent_id,
        (atq.created_at AT TIME ZONE 'UTC')::date AS stat_date,
        COUNT(*)::bigint AS run_count,
        0::bigint AS task_count,
        0::bigint AS failed_count
    FROM agent_task_queue atq
    JOIN agent a ON a.id = atq.agent_id
    GROUP BY a.workspace_id, atq.agent_id, (atq.created_at AT TIME ZONE 'UTC')::date

    UNION ALL

    SELECT
        a.workspace_id,
        atq.agent_id,
        (atq.completed_at AT TIME ZONE 'UTC')::date AS stat_date,
        0::bigint AS run_count,
        COUNT(*)::bigint AS task_count,
        COUNT(*) FILTER (WHERE atq.status = 'failed')::bigint AS failed_count
    FROM agent_task_queue atq
    JOIN agent a ON a.id = atq.agent_id
    WHERE atq.completed_at IS NOT NULL
    GROUP BY a.workspace_id, atq.agent_id, (atq.completed_at AT TIME ZONE 'UTC')::date
)
INSERT INTO agent_daily_stats (
    workspace_id, agent_id, stat_date,
    run_count, task_count, failed_count
)
SELECT
    workspace_id,
    agent_id,
    stat_date,
    SUM(run_count),
    SUM(task_count),
    SUM(failed_count)
FROM contributions
GROUP BY workspace_id, agent_id, stat_date
ON CONFLICT (workspace_id, agent_id, stat_date) DO UPDATE
SET run_count = EXCLUDED.run_count,
    task_count = EXCLUDED.task_count,
    failed_count = EXCLUDED.failed_count;

COMMIT;
