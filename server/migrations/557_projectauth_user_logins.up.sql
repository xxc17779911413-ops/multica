-- 2026-09-06 coder(lq): Track successful interactive logins separately from
-- organization-directory imports so authorization browsers can show whether
-- a synchronized employee has actually signed in to Multica.
CREATE TABLE IF NOT EXISTS projectauth_user_logins (
    user_id UUID NOT NULL PRIMARY KEY,
    last_logged_in_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
