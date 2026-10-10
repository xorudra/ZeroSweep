#!/usr/bin/env bash
# Render start script for the DSRclone API service.
# Applies database migrations and the (idempotent) seed, then starts the API.
# Mirrors scripts/local-stack/start.sh so the Render demo and the local
# stack boot the same way.
#
# Launch Safety B20: migrations run with MIGRATION_DATABASE_URL when it is
# set (a privileged, migration-only connection), falling back to
# DATABASE_URL so existing deployments behave exactly as before. The seed
# and the API process itself always use DATABASE_URL — the application
# role needs no DDL rights once migrations have run.
set -e
cd "$(dirname "$0")/../.."
DATABASE_URL="${MIGRATION_DATABASE_URL:-$DATABASE_URL}" pnpm --filter @dsrclone/database exec prisma migrate deploy
pnpm --filter @dsrclone/database exec tsx prisma/seed.ts
exec node apps/api/dist/main.js
