#!/usr/bin/env bash
# Apply all authorize-svc migrations to a Postgres database, in order.
#
#   DATABASE_URL="postgres://…?sslmode=require" ./deploy/apply-migrations.sh
#
# Idempotent: every migration uses IF NOT EXISTS / ADD COLUMN IF NOT EXISTS.
set -euo pipefail

: "${DATABASE_URL:?set DATABASE_URL (e.g. a Neon connection string)}"

dir="$(cd "$(dirname "$0")/migrations" && pwd)"
for f in "$dir"/[0-9]*.sql; do
  echo ">> applying $(basename "$f")"
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f "$f"
done
echo "migrations applied."
