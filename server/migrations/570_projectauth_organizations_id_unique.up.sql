-- 2026-09-07 coder(lq): Preserve uniqueness of synchronized organization
-- identifiers for unambiguous grant references.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_organizations_id_uniq
    ON projectauth_organizations (id);
