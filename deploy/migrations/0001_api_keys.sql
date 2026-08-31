-- 0001_api_keys.sql — API key store (TRD §11, ROADMAP Task 1.2).
--
-- The service stores ONLY sha256(key); the raw key is never persisted. key_id is a
-- public, non-secret identifier (env prefix + a prefix of the hash) used for O(1)
-- lookup and safe to log. Constant-time verification happens in the service, not in
-- SQL, so the query is a plain indexed equality on the public id.
--
-- Apply locally:  psql "$DATABASE_URL" -f deploy/migrations/0001_api_keys.sql

CREATE TABLE IF NOT EXISTS api_keys (
    key_id      TEXT        PRIMARY KEY,                 -- public id (azn_live_<hashprefix>)
    key_sha256  TEXT        NOT NULL,                    -- hex sha256(rawKey); the only stored key form
    org_id      TEXT        NOT NULL,
    tier        TEXT        NOT NULL DEFAULT 'default',  -- drives rate limits (Task 1.3)
    env         TEXT        NOT NULL CHECK (env IN ('live', 'test')),
    status      TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMPTZ
);

-- Uniqueness of the stored hash guards against duplicate key material.
CREATE UNIQUE INDEX IF NOT EXISTS api_keys_key_sha256_uniq ON api_keys (key_sha256);

-- Common filter for a tenant's keys.
CREATE INDEX IF NOT EXISTS api_keys_org_id_idx ON api_keys (org_id);
