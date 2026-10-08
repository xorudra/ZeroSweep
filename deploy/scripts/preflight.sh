#!/bin/sh
# DSRclone production preflight (Prompt 25 §30/§165/§185).
# Verifies the OPERATOR side of a deployment without printing any secret:
# required variable NAMES present, placeholder values rejected, tooling
# present, and the production compose file parses. Values are never echoed.
set -u

ENV_FILE="${1:-deploy/compose/.env.production}"
COMPOSE_FILE="deploy/compose/docker-compose.production.yml"
FAIL=0

echo "[preflight] env file: $ENV_FILE"
if [ ! -f "$ENV_FILE" ]; then
  echo "[preflight] FAIL: env file not found (copy .env.production.example and fill via your secret store)"
  exit 1
fi

for VAR in DSRCLONE_VERSION DATABASE_URL REDIS_URL REDIS_PASSWORD POSTGRES_PASSWORD JWT_SECRET API_CORS_ORIGIN; do
  if ! grep -q "^${VAR}=." "$ENV_FILE"; then
    echo "[preflight] FAIL: $VAR is missing or empty"
    FAIL=1
  fi
done
if grep -Eq 'change-me|REPLACE-(WITH|FROM)' "$ENV_FILE"; then
  echo "[preflight] FAIL: placeholder values remain in the env file"
  FAIL=1
fi

# JWT length check without printing the value.
JWT_LEN=$(grep '^JWT_SECRET=' "$ENV_FILE" | cut -d= -f2- | tr -d '\r' | wc -c)
if [ "$JWT_LEN" -lt 33 ]; then
  echo "[preflight] FAIL: JWT_SECRET is shorter than 32 characters"
  FAIL=1
fi

echo "[preflight] tooling"
command -v docker >/dev/null 2>&1 && echo "[preflight] docker: present" || echo "[preflight] note: docker not on PATH (fine if deploying to Kubernetes only)"
command -v kubectl >/dev/null 2>&1 && echo "[preflight] kubectl: present" || echo "[preflight] note: kubectl not on PATH (fine if deploying with Compose only)"

if command -v docker >/dev/null 2>&1; then
  if docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" config --quiet 2>/dev/null; then
    echo "[preflight] compose file parses with the supplied env"
  else
    echo "[preflight] FAIL: compose file does not parse with the supplied env"
    FAIL=1
  fi
fi

if [ "$FAIL" -ne 0 ]; then
  echo "[preflight] RESULT: FAILED — fix the items above before deploying"
  exit 1
fi
echo "[preflight] RESULT: OK"
