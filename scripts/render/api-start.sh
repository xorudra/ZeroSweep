#!/usr/bin/env bash
# Render start script for the DSRclone API service.
# Applies database migrations and the (idempotent) seed, then starts the API.
# Mirrors scripts/local-stack/start.sh so the Render demo and the local
# stack boot the same way.
set -e
cd "$(dirname "$0")/../.."
pnpm --filter @dsrclone/database exec prisma migrate deploy
pnpm --filter @dsrclone/database exec tsx prisma/seed.ts
exec node apps/api/dist/main.js
