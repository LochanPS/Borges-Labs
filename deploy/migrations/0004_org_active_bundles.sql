-- 0004_org_active_bundles.sql — the per-org "active bundle" pointer (ROADMAP Task 2.2,
-- A#4 "stale policy = wrong decision").
--
-- One row per org names the single published policy version currently serving that
-- org's decision plane (the one-active-bundle-per-org MVP model). Publishing or rolling
-- back a policy upserts this pointer; the decision plane converges to it (immediately
-- in-process, within the refresh TTL across instances) and every decision cites the
-- version_hash named here. GET /v1/policies/active reads this row.
--
-- Unlike policy_versions, this pointer is MUTABLE (it moves on every publish/rollback),
-- so no append-only trigger. The immutable, signed history lives in policy_versions;
-- this is just "which one is live".
--
-- Apply locally:  psql "$DATABASE_URL" -f deploy/migrations/0004_org_active_bundles.sql

CREATE TABLE IF NOT EXISTS org_active_bundles (
    org_id       TEXT        PRIMARY KEY,
    policy_id    TEXT        NOT NULL REFERENCES policies (id),
    version_hash TEXT        NOT NULL REFERENCES policy_versions (version_hash),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
