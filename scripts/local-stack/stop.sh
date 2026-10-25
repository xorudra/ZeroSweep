#!/bin/bash
# Stop the ZeroSweep local stack (app processes, Redis, PostgreSQL).
STACK="$HOME/workspace/zerosweep-local-stack"
pkill -f "apps/api/dist/main.js" 2>/dev/null && echo "[stack] api stopped" || true
pkill -f "apps/worker/dist/index.js" 2>/dev/null && echo "[stack] worker stopped" || true
pkill -f "apps/api/dist/scheduler-main.js" 2>/dev/null && echo "[stack] scheduler stopped" || true
pkill -f "uvicorn app.main:app" 2>/dev/null && echo "[stack] ai stopped" || true
"$STACK/redis-7.2.5/src/redis-cli" -p 6379 shutdown nosave 2>/dev/null && echo "[stack] redis stopped" || true
SP="$STACK/venv/lib/python3.12/site-packages"
if [ -x "$SP/pgserver/pginstall/bin/pg_ctl" ]; then
  setpriv --reuid=65534 --regid=65534 --clear-groups \
    env LD_LIBRARY_PATH="$SP/pgserver.libs:$SP/pgserver/pginstall/lib" \
    "$SP/pgserver/pginstall/bin/pg_ctl" -D "$STACK/pgdata" -m fast stop >/dev/null 2>&1 \
    && echo "[stack] postgres stopped" || echo "[stack] postgres was not running"
fi
