-- 2026-09-07 coder(lq): Restore the project-grant idempotency index after
-- the authorization migrations were renumbered around main's private stream.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_access_grants_project_uniq
    ON projectauth_access_grants (project_id, subject_type, subject_id, COALESCE(role_key, ''), COALESCE(permission, ''))
    WHERE issue_id IS NULL;
