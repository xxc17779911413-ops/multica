-- Recently viewed issues per user, cross-device. One row per (user, issue);
-- re-viewing updates viewed_at in place so the table stays bounded.
CREATE TABLE issue_view_events (
    workspace_id UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    issue_id UUID NOT NULL REFERENCES issue(id) ON DELETE CASCADE,
    viewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, issue_id)
);

CREATE INDEX issue_view_events_user_recent_idx
    ON issue_view_events (user_id, workspace_id, viewed_at DESC);
