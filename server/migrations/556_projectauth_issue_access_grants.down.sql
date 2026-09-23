-- 2026-09-05 coder(lq): Roll back only the projectless task grant storage.
DROP TABLE IF EXISTS projectauth_issue_access_grants;
