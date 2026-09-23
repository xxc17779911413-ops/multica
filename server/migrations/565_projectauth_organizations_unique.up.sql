-- 2026-09-07 coder(lq): Ensure one synchronized directory row per external
-- organization within a workspace and provider.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS projectauth_organizations_workspace_provider_external_uniq
    ON projectauth_organizations (workspace_id, provider, external_id);
