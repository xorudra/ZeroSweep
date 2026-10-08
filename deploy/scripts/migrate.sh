#!/bin/sh
# DSRclone controlled migration runner (Prompt 25 §36–§39).
# Preflight -> migrate deploy -> post-verification. Exits non-zero on any
# failure so orchestrators (compose depends_on, K8s Job) block the rollout.
# NEVER prints DATABASE_URL or any credential value.
set -eu

PRISMA="node_modules/.bin/prisma"
SCHEMA="packages/database/prisma/schema.prisma"
export PRISMA_SCHEMA_PATH="$SCHEMA"

echo "[migrate] preflight: environment"
if [ -z "${DATABASE_URL:-}" ]; then
  echo "[migrate] FATAL: DATABASE_URL is not set" >&2
  exit 1
fi
case "$DATABASE_URL" in
  *change-me*|*REPLACE-*)
    if [ "${NODE_ENV:-}" = "production" ]; then
      echo "[migrate] FATAL: DATABASE_URL still contains a placeholder value" >&2
      exit 1
    fi
    ;;
esac
if [ ! -d packages/database/prisma/migrations ]; then
  echo "[migrate] FATAL: migrations directory missing from image" >&2
  exit 1
fi
MIGRATION_COUNT=$(find packages/database/prisma/migrations -maxdepth 1 -mindepth 1 -type d | wc -l)
echo "[migrate] preflight: $MIGRATION_COUNT migrations packaged"

echo "[migrate] preflight: database reachability (bounded wait)"
ATTEMPT=0
until $PRISMA migrate status >/dev/null 2>&1; do
  ATTEMPT=$((ATTEMPT + 1))
  if [ "$ATTEMPT" -ge 30 ]; then
    echo "[migrate] FATAL: database not reachable / migration status failed after 30 attempts" >&2
    $PRISMA migrate status || true
    exit 1
  fi
  sleep 2
done

echo "[migrate] status before deploy:"
$PRISMA migrate status || true

echo "[migrate] applying migrations (prisma migrate deploy)"
$PRISMA migrate deploy

echo "[migrate] post-check: migration status"
$PRISMA migrate status
echo "[migrate] OK: database schema is at the packaged migration head"
