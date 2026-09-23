-- 2026-09-14 coder(lq): Supply an application-maintained request identity.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_requests_id_uidx
    ON projectauth_access_requests (id);
