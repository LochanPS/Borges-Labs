-- 0006_budget_reservations.sql — the source-of-truth ledger for two-phase budget
-- holds (ROADMAP Task 3.1/3.2, TRD §12–13, §17).
--
-- Each row is one reservation placed by a budget-affecting APPROVE. The Redis counter
-- (budget:<org>:<budget_id>:<window_key>) is the FAST atomic gate that prevents
-- oversell on the hot path; THIS table is the durable source of truth the counter is
-- reconciled against — TTL expiry releases (held→expired) and drift rebuilds
-- (counter := sum of held+captured amounts for a window) both read from here.
--
-- State machine: held → captured | voided | expired (see internal/hold). captured
-- spend persists; voided/expired release the counter. Rows are updated in place as
-- state transitions (not append-only — the audit log, migration 0002, is the immutable
-- record; this is mutable operational state).
--
-- Apply locally:  psql "$DATABASE_URL" -f deploy/migrations/0006_budget_reservations.sql

CREATE TABLE IF NOT EXISTS budget_reservations (
    org_id       TEXT        NOT NULL,
    decision_id  TEXT        NOT NULL,               -- the hold handle (ULID); capture/void address it
    agent_id     TEXT        NOT NULL,
    budget_id    TEXT        NOT NULL,
    window       TEXT        NOT NULL,               -- day | month | rolling
    window_key   TEXT        NOT NULL,               -- concrete period, e.g. 2026-09
    amount       TEXT        NOT NULL,               -- canonical decimal string
    currency     TEXT        NOT NULL,
    state        TEXT        NOT NULL DEFAULT 'held'
                 CHECK (state IN ('held', 'captured', 'voided', 'expired')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    captured_at  TIMESTAMPTZ,
    voided_at    TIMESTAMPTZ,
    PRIMARY KEY (org_id, decision_id)
);

-- Reconciler: find held reservations past their TTL to release.
CREATE INDEX IF NOT EXISTS budget_reservations_due_idx
    ON budget_reservations (expires_at) WHERE state = 'held';

-- Rebuild a window's counter from the source of truth (held + captured spend).
CREATE INDEX IF NOT EXISTS budget_reservations_window_idx
    ON budget_reservations (org_id, budget_id, window_key, state);
