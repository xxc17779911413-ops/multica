-- 2026-09-21 coder(lq): Remember that a manager withdrew the access a mention
-- granted, without freezing the task against future mentions.
--
-- Mentioning somebody stores a real task grant (source='system'), and every
-- comment or description change reconciles that storage against the text: who is
-- still mentioned keeps the grant, everyone else loses it. That makes deleting a
-- comment a way to withdraw the access (fixed in the same release), but it leaves
-- no way to withdraw it while the mention is still in the text.
--
-- A row here records that decision for one (task, person). Reconciliation skips a
-- mention that is no longer NEWER than revoked_at, so:
--
--   * the mention that was revoked stays revoked, however often the task is
--     edited or commented on;
--   * mentioning the person again — a new comment, or an edit to an existing one
--     — carries a timestamp after revoked_at and grants the access again, which
--     is what "unless you mention them again" has to mean;
--   * a mention in the DESCRIPTION has no timestamp of its own, so the digest of
--     the description at revocation time is stored instead: the description's
--     mentions count again only once that text actually changes.
--
-- The row is deliberately left in place after a later mention re-grants access:
-- it is inert from that point on (every fresh mention outranks it), and removing
-- it would need a second write on a path that only ever reads.
--
-- No foreign keys by house rule; the subject is re-validated by the caller. The
-- unique key is built by the next migration with CREATE INDEX CONCURRENTLY, as
-- every index in this repository is.
CREATE TABLE IF NOT EXISTS projectauth_issue_mention_revocations (
    workspace_id       UUID NOT NULL,
    issue_id           UUID NOT NULL,
    subject_id         TEXT NOT NULL,
    revoked_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_by         UUID,
    description_digest TEXT NOT NULL DEFAULT ''
);
