-- 0005_api_keys_shadow.sql — per-key shadow (advisory) flag (ROADMAP Task 2.3, A#5).
--
-- A shadow key's decisions are evaluated and audited but marked shadow=true so the
-- caller does NOT enforce them (advisory-first rollout). Default TRUE: a new key runs
-- in shadow until it is deliberately flipped to enforce (shadow=false) — the go/no-go
-- lever for one agent at a time (ROADMAP §6.1).
--
-- Apply locally:  psql "$DATABASE_URL" -f deploy/migrations/0005_api_keys_shadow.sql

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS shadow BOOLEAN NOT NULL DEFAULT TRUE;
