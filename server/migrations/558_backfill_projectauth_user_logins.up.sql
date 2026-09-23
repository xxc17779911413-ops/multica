-- 2026-09-06 coder(lq): Preserve the login state of users created before
-- projectauth_user_logins existed. `onboarded_at` is the historical marker
-- available for accounts that completed the interactive signup flow. Owners
-- and admins are also legacy authenticated-user signals: those roles could
-- only be assigned from an authenticated workspace action. Directory imports
-- create ordinary members and do not set either signal.
INSERT INTO projectauth_user_logins (user_id, last_logged_in_at)
SELECT u.id, COALESCE(u.onboarded_at, u.created_at)
FROM "user" u
WHERE u.onboarded_at IS NOT NULL
   OR EXISTS (
       SELECT 1
       FROM member m
       WHERE m.user_id = u.id
         AND m.role IN ('owner', 'admin')
   )
ON CONFLICT (user_id) DO NOTHING;
