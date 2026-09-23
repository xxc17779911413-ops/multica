-- 2026-09-07 coder(lq): Preserve uniqueness of generated grant identifiers.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_grants_id_uniq
    ON projectauth_access_grants (id);
