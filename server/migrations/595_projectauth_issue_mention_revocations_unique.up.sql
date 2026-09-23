-- One revocation per (task, person): re-revoking an already-revoked subject
-- refreshes the timestamp rather than stacking rows, so reconciliation has a
-- single watermark to compare a mention against.
--
-- Kept as its own file because CREATE INDEX CONCURRENTLY cannot run inside a
-- transaction or beside another statement (repository migration rule).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_issue_mention_revocations_subject_uidx
    ON projectauth_issue_mention_revocations (workspace_id, issue_id, subject_id);
