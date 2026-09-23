-- 2026-09-14 coder(lq): Durable per-recipient delivery ledger for task access
-- requests. The inbox row and this ledger are written in the request/review
-- transaction, making retries safe without coupling the generic inbox table to
-- the private authorization model.
CREATE TABLE IF NOT EXISTS projectauth_access_request_notifications (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    request_id UUID NOT NULL,
    recipient_user_id UUID NOT NULL,
    event TEXT NOT NULL CHECK (event IN ('requested', 'approved', 'rejected', 'cancelled', 'expired')),
    inbox_item_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
