-- Password sign-in. Empty hash = account has no password yet: the
-- verification-code flow stays available exactly once (registration or the
-- one-time migration bridge) and requires setting one.
ALTER TABLE "user" ADD COLUMN password_hash TEXT NOT NULL DEFAULT '';
