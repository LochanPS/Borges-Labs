-- 0002_decisions.sql — append-only audit log of decisions (TRD §12–13, §14; ROADMAP Task 1.6, A#10).
--
-- Every decision returned by POST /v1/authorize is persisted here ASYNCHRONOUSLY,
-- off the request's hot path (the write never adds to latency_ms). The table is the
-- tamper-evident system of record:
--
--   * APPEND-ONLY. A trigger blocks UPDATE and DELETE at the storage layer, and the
--     application role should additionally be GRANTed only INSERT/SELECT (see below).
--     Retention (A#10) is enforced by crypto-shredding the per-tier data-encryption
--     key once retain_until passes — NOT by deleting rows — so append-only holds.
--
--   * HASH-CHAINED per org. record_hash = H(prev_hash ‖ canonical(record)) where the
--     canonical form is RFC 8785 JCS over the record's fields (see internal/audit).
--     Each org's records form a chain: mutate any stored field and the recomputed
--     record_hash no longer matches; rewrite a record_hash and the next record's
--     prev_hash no longer links. Read-time verification recomputes the hash and the
--     Ed25519 signature, surfacing signature_verified (contract: decision.schema.json).
--
--   * FIELD-LEVEL ENCRYPTION on the sensitive fields amount/target (A#10). Those
--     columns hold ciphertext (AES-256-GCM, base64) when a key is configured, or the
--     plaintext when it is not (dev/CI). The record_hash is always computed over the
--     PLAINTEXT, so a third party who can decrypt can independently recompute it.
--     Non-sensitive fields used as filters (agent_id, verdict, evaluated_at) stay
--     plaintext so the list endpoint can index/filter them.
--
-- Apply locally:  psql "$DATABASE_URL" -f deploy/migrations/0002_decisions.sql

CREATE TABLE IF NOT EXISTS decisions (
    seq                 BIGSERIAL   PRIMARY KEY,             -- global insertion order; drives pagination
    decision_id         TEXT        NOT NULL,                -- ULID from the Decision (unique within an org)
    org_id              TEXT        NOT NULL,
    api_key_id          TEXT        NOT NULL,                -- which key produced it (public id; safe to store)

    -- request-derived, non-sensitive (kept plaintext for filtering/indexing)
    agent_id            TEXT        NOT NULL,
    action              TEXT        NOT NULL,
    currency            TEXT        NOT NULL,
    jurisdiction        TEXT        NOT NULL DEFAULT '',

    -- request-derived, SENSITIVE (A#10): ciphertext at rest when a key is configured
    amount_enc          TEXT        NOT NULL,                -- encrypts req.amount
    target_type_enc     TEXT        NOT NULL,                -- encrypts req.target.type
    target_id_enc       TEXT        NOT NULL,                -- encrypts req.target.id (the counterparty)

    -- decision content (the signed receipt + read-time reconstruction inputs)
    verdict             TEXT        NOT NULL CHECK (verdict IN ('APPROVE', 'DENY', 'REVIEW')),
    policy_version_hash TEXT        NOT NULL,
    explanation         JSONB       NOT NULL,                -- includes matched_rules (TRD §7)
    obligations         JSONB       NOT NULL,
    signature           JSONB       NOT NULL,                -- {algorithm,key_id,value,canonicalization}
    latency_ms          INTEGER     NOT NULL,
    evaluated_at        TEXT        NOT NULL,                -- exact signed bytes (RFC 3339 string)
    evaluated_at_ts     TIMESTAMPTZ NOT NULL,                -- parsed, for range filtering/ordering
    shadow              BOOLEAN     NOT NULL DEFAULT FALSE,

    -- tamper-evidence chain
    prev_hash           TEXT        NOT NULL,                -- record_hash of the org's previous record (genesis for the first)
    record_hash         TEXT        NOT NULL,

    -- retention (A#10): when the sensitive ciphertext becomes eligible for crypto-shred
    retain_until        TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A decision_id is unique within an org (idempotent re-append is a no-op via ON CONFLICT).
CREATE UNIQUE INDEX IF NOT EXISTS decisions_org_decision_uniq ON decisions (org_id, decision_id);

-- Chain integrity: at most one record per (org, prev_hash) keeps the per-org chain linear.
CREATE UNIQUE INDEX IF NOT EXISTS decisions_org_prevhash_uniq ON decisions (org_id, prev_hash);

-- List/read indexes (TRD §12).
CREATE INDEX IF NOT EXISTS decisions_org_seq_idx        ON decisions (org_id, seq DESC);
CREATE INDEX IF NOT EXISTS decisions_org_agent_seq_idx  ON decisions (org_id, agent_id, seq DESC);
CREATE INDEX IF NOT EXISTS decisions_org_evalat_idx     ON decisions (org_id, evaluated_at_ts);

-- Append-only enforcement (defense in depth). The application role must never be
-- granted UPDATE/DELETE; this trigger makes a mutation impossible even if it is.
CREATE OR REPLACE FUNCTION decisions_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'decisions is append-only: % is not permitted', TG_OP
        USING ERRCODE = 'restrict_violation';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS decisions_no_mutate ON decisions;
CREATE TRIGGER decisions_no_mutate
    BEFORE UPDATE OR DELETE ON decisions
    FOR EACH ROW EXECUTE FUNCTION decisions_append_only();

-- Recommended, run once by a privileged migration/owner role (left commented so the
-- bootstrap DSN — often the owner — is not locked out of applying migrations):
--   REVOKE UPDATE, DELETE, TRUNCATE ON decisions FROM authz;
--   GRANT  INSERT, SELECT             ON decisions TO   authz;
