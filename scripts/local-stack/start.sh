#!/bin/bash
# DSRclone Docker-less local stack (Prompt 25 provisioning).
# PostgreSQL via pgserver's bundled binaries (run as user `nobody` — PG
# refuses root), Redis from the official source tarball, then migrations,
# seed, and the API/worker/AI processes from this repo.
# Idempotent: safe to re-run; skips work that is already done.
set -u
STACK="$HOME/workspace/dsrclone-local-stack"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$STACK"
cd "$STACK"

# --- Python venv + pgserver -------------------------------------------------
if [ ! -d venv ]; then
  python3 -m venv venv || { echo "FATAL: python3 venv failed"; exit 1; }
fi
if [ ! -d venv/lib/python3.12/site-packages/pgserver ]; then
  ./venv/bin/pip install --quiet pgserver || { echo "FATAL: pip install pgserver failed"; exit 1; }
  chmod -R a+rX venv   # the unprivileged pg user must read the binaries
fi
SP="$STACK/venv/lib/python3.12/site-packages"
PGB="$SP/pgserver/pginstall"
export LD_LIBRARY_PATH="$SP/pgserver.libs:$PGB/lib"

# --- PostgreSQL --------------------------------------------------------------
if [ ! -d pgdata ]; then
  mkdir -p pgdata pgsock && chown 65534:65534 pgdata pgsock && chmod 700 pgdata
  setpriv --reuid=65534 --regid=65534 --clear-groups bash -c \
    "export LD_LIBRARY_PATH='$LD_LIBRARY_PATH'; '$PGB/bin/initdb' -D '$STACK/pgdata' -U dsrclone -A trust --no-instructions -E UTF8 --locale=C" \
    || { echo "FATAL: initdb failed"; exit 1; }
fi
if ! "$PGB/bin/pg_isready" -h 127.0.0.1 -p 54329 >/dev/null 2>&1; then
  setsid setpriv --reuid=65534 --regid=65534 --clear-groups bash -c \
    "export LD_LIBRARY_PATH='$LD_LIBRARY_PATH'; exec '$PGB/bin/postgres' -D '$STACK/pgdata' -p 54329 -k '$STACK/pgsock' -c listen_addresses=127.0.0.1" \
    >> "$STACK/pg.log" 2>&1 &
  for i in $(seq 1 30); do "$PGB/bin/pg_isready" -h 127.0.0.1 -p 54329 >/dev/null 2>&1 && break; sleep 1; done
fi
"$PGB/bin/pg_isready" -h 127.0.0.1 -p 54329 || { echo "FATAL: postgres did not start; see $STACK/pg.log"; exit 1; }
"$PGB/bin/createdb" -h 127.0.0.1 -p 54329 -U dsrclone dsrclone 2>/dev/null || true
echo "[stack] postgres: accepting connections on 127.0.0.1:54329"

# --- Redis -------------------------------------------------------------------
if [ ! -x redis-7.2.5/src/redis-server ]; then
  curl -fsSL -o redis.tar.gz https://download.redis.io/releases/redis-7.2.5.tar.gz \
    && tar xzf redis.tar.gz || { echo "FATAL: redis download failed"; exit 1; }
  ( cd redis-7.2.5 && make -j"$(nproc)" MALLOC=libc >/dev/null ) || { echo "FATAL: redis build failed"; exit 1; }
fi
if ! ./redis-7.2.5/src/redis-cli -p 6379 ping >/dev/null 2>&1; then
  mkdir -p redisdata
  ./redis-7.2.5/src/redis-server --port 6379 --bind 127.0.0.1 --daemonize yes \
    --dir "$STACK/redisdata" --appendonly yes --save '' --logfile "$STACK/redis.log"
fi
./redis-7.2.5/src/redis-cli -p 6379 ping || { echo "FATAL: redis did not start"; exit 1; }
echo "[stack] redis: PONG on 127.0.0.1:6379"

# --- Env ----------------------------------------------------------------------
if [ ! -f smoke.env ]; then
  python3 - <<'PYEOF'
import secrets
lines = {
 "DATABASE_URL": "postgresql://dsrclone@127.0.0.1:54329/dsrclone?schema=public",
 "REDIS_URL": "redis://127.0.0.1:6379",
 "JWT_SECRET": secrets.token_hex(32),
 "API_PORT": "4000",
 "NODE_ENV": "development",
 "MINIO_ENDPOINT": "http://127.0.0.1:9000",
 "AI_SERVICE_URL": "http://127.0.0.1:8000",
}
with open("smoke.env", "w") as f:
    for k, v in lines.items():
        f.write(f"{k}={v}\n")
print("[stack] smoke.env generated (local JWT secret)")
PYEOF
fi
export DATABASE_URL="postgresql://dsrclone@127.0.0.1:54329/dsrclone?schema=public"

# --- Migrate + seed ------------------------------------------------------------
( cd "$REPO/packages/database" && npx prisma migrate deploy >/dev/null ) \
  && echo "[stack] migrations: applied (prisma migrate deploy)" || { echo "FATAL: migrations failed"; exit 1; }
( cd "$REPO/packages/database" && npx tsx prisma/seed.ts ) \
  && echo "[stack] seed: applied" || { echo "FATAL: seed failed"; exit 1; }

# --- MinIO object storage (Prompt 38) -------------------------------------------
# Provisioned from the official MinIO source release built with the
# official Go toolchain (the prebuilt download endpoints returned
# 410/404 in this environment; see docs/architecture/
# production-deployment-v2.md and the Phase 38 notes). Binary +
# credentials live under $STACK/minio (local-only, never committed).
# If the binary is absent, health reports object storage down — the
# honest status, never a fabricated one.
if [ -x "$STACK/minio/minio" ]; then
  if [ ! -f "$STACK/minio/minio.env" ]; then
    umask 077
    printf 'MINIO_ROOT_USER=dsrclone-local\nMINIO_ROOT_PASSWORD=%s\n' \
      "$(python3 -c 'import secrets; print(secrets.token_hex(24))')" > "$STACK/minio/minio.env"
  fi
  if ! curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; then
    mkdir -p "$STACK/minio/data"
    ( cd "$STACK/minio" && set -a && . ./minio.env && set +a && \
      setsid nohup ./minio server "$STACK/minio/data" --address 127.0.0.1:9000 \
        --console-address 127.0.0.1:9001 >>"$STACK/minio/minio.log" 2>&1 & )
    for i in $(seq 1 30); do
      curl -sf http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1 && break
      sleep 1
    done
  fi
  echo "[stack] MinIO: running at http://127.0.0.1:9000 (console 9001)"
else
  echo "[stack] MinIO: not provisioned under $STACK/minio — health reports object storage down."
fi

# Platform operations env (Prompt 38): pg tools for the backup
# orchestrator, a local backup dir, and an operator passphrase file so
# live backups are encrypted (§166). Appended to smoke.env if absent.
ensure_env() { grep -q "^$1=" "$STACK/smoke.env" 2>/dev/null || echo "$1=$2" >> "$STACK/smoke.env"; }
mkdir -p "$STACK/backups"
[ -f "$STACK/backup-passphrase" ] || { umask 077; openssl rand -hex 24 > "$STACK/backup-passphrase"; }
PG_BIN="$STACK/venv/lib/python3.12/site-packages/pgserver/pginstall/bin"
ensure_env PG_BIN_DIR "$PG_BIN"
ensure_env PLATFORM_BACKUP_DIR "$STACK/backups"
ensure_env PLATFORM_BACKUP_PASSPHRASE_FILE "$STACK/backup-passphrase"
if [ -f "$STACK/minio/minio.env" ]; then
  ensure_env MINIO_ROOT_USER "$(grep '^MINIO_ROOT_USER=' "$STACK/minio/minio.env" | cut -d= -f2)"
  ensure_env MINIO_ROOT_PASSWORD "$(grep '^MINIO_ROOT_PASSWORD=' "$STACK/minio/minio.env" | cut -d= -f2)"
fi

# --- App processes ---------------------------------------------------------------
cd "$REPO"
if ! curl -sf http://127.0.0.1:4000/api/v1/health/live >/dev/null 2>&1; then
  setsid nohup env $(grep -v '^#' "$STACK/smoke.env" | xargs) node apps/api/dist/main.js >> "$STACK/api.log" 2>&1 < /dev/null &
fi
if ! pgrep -f "apps/worker/dist/index.js" >/dev/null; then
  setsid nohup env $(grep -v '^#' "$STACK/smoke.env" | xargs) node apps/worker/dist/index.js >> "$STACK/worker.log" 2>&1 < /dev/null &
fi
if [ ! -d "$STACK/venv/lib/python3.12/site-packages/fastapi" ]; then
  "$STACK/venv/bin/pip" install --quiet "fastapi>=0.115,<1.0" "uvicorn[standard]>=0.30" "pydantic>=2.7" || true
fi
if ! curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then
  setsid nohup "$STACK/venv/bin/python" -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --app-dir "$REPO/apps/ai" >> "$STACK/ai.log" 2>&1 < /dev/null &
fi
sleep 5
curl -s http://127.0.0.1:4000/api/v1/health && echo
echo "[stack] up. Smoke: node $REPO/scripts/local-stack/smoke.mjs"
