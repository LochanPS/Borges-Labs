-- 0003_policies.sql — control-plane policy authoring + immutable signed versions
-- (TRD §6, §12; ROADMAP Task 2.1, A#6 "no compiler", A2#2 "control plane folded into
-- the Go service for MVP").
--
-- Two tables, two lifecycles:
--
--   * policies      — the MUTABLE working copy an org authors and edits. One row per
--                     policy. `document` holds the current draft (name/agents/rules);
--                     `active_version_hash` points at the immutable version currently
--                     designated to serve (NULL until first publish). status is
--                     draft until the first publish, then published.
--
--   * policy_versions — IMMUTABLE, content-addressed, Ed25519-signed snapshots. On
--                     publish the working copy is validated, canonicalized (RFC 8785
--                     JCS over identity+rules), SHA-256'd into `version_hash`, and
--                     signed. Identical content re-publishes to the SAME hash (ON
--                     CONFLICT DO NOTHING makes republish/rollback idempotent); any
--                     edit yields a new hash and a new row. Every decision cites the
--                     version hash it evaluated under (Task 2.2); rollback re-points
--                     policies.active_version_hash at a prior hash — no row is rewritten.
--                     APPEND-ONLY: a trigger blocks UPDATE/DELETE (same pattern as
--                     decisions, migration 0002), so a signed version can never change
--                     under an auditor's feet.
--
-- Apply locally:  psql "$DATABASE_URL" -f deploy/migrations/0003_policies.sql

CREATE TABLE IF NOT EXISTS policies (
    id                  TEXT        PRIMARY KEY,             -- pol_<ULID>
    org_id              TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    agents              JSONB       NOT NULL DEFAULT '[]',   -- targeted agent ids ([] = all)
    rules               JSONB       NOT NULL DEFAULT '[]',   -- current working-copy rules
    status              TEXT        NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'published')),
    active_version_hash TEXT,                                -- FK-by-value into policy_versions; NULL until published
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS policies_org_idx ON policies (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_versions (
    version_hash        TEXT        PRIMARY KEY,             -- polv_<sha256>: content hash of identity+rules
    policy_id           TEXT        NOT NULL REFERENCES policies (id),
    org_id              TEXT        NOT NULL,
    name                TEXT        NOT NULL,
    agents              JSONB       NOT NULL,
    rules               JSONB       NOT NULL,
    signature           JSONB       NOT NULL,                -- {algorithm,key_id,value,canonicalization}
    author              TEXT        NOT NULL DEFAULT '',
    parent_hash         TEXT,                                -- version this one superseded at publish ("" / NULL if first)
    published_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- List a policy's versions newest-first (Task 2.1 "list versions").
CREATE INDEX IF NOT EXISTS policy_versions_policy_idx ON policy_versions (org_id, policy_id, published_at DESC);

-- Append-only enforcement (defense in depth): a signed version is immutable. The
-- application role should also be GRANTed only INSERT/SELECT on policy_versions.
CREATE OR REPLACE FUNCTION policy_versions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'policy_versions is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS policy_versions_no_mutate ON policy_versions;
CREATE TRIGGER policy_versions_no_mutate
    BEFORE UPDATE OR DELETE ON policy_versions
    FOR EACH ROW EXECUTE FUNCTION policy_versions_append_only();

-- Recommended, run once by a privileged role (commented so the bootstrap DSN — often
-- the owner — is not locked out of applying migrations):
--   REVOKE UPDATE, DELETE, TRUNCATE ON policy_versions FROM authz;
--   GRANT  INSERT, SELECT             ON policy_versions TO   authz;
