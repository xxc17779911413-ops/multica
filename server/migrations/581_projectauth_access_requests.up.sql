-- 2026-09-14 coder(lq): Store task-role access requests independently from
-- grants; approval will create a normal grant plus provenance atomically.
CREATE TABLE IF NOT EXISTS projectauth_access_requests (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    issue_id UUID NOT NULL,
    requester_user_id UUID NOT NULL,
    requested_role_key TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'expired')),
    reviewer_user_id UUID,
    review_comment TEXT NOT NULL DEFAULT '',
    grant_expires_at TIMESTAMPTZ,
    idempotency_key TEXT NOT NULL,
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (length(btrim(requested_role_key)) > 0),
    CHECK (length(btrim(idempotency_key)) > 0),
    CHECK (grant_expires_at IS NULL OR grant_expires_at > created_at)
);
