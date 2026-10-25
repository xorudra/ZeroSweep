#!/bin/bash
# ZeroSweep controlled resilience tests — LOCAL STACK SUBSET (Prompt 25
# §153–§172). The Kubernetes-only items (pod kills, NetworkPolicy and
# admission-policy rejections, metadata SSRF block) are validated by
# manifest inspection + policy tests on a cluster; this script exercises
# the items a local stack can prove:
#   R1 API process kill + restart  -> persisted state survives (§153)
#   R2 Redis pause                 -> liveness stays 200, readiness goes
#                                   503, recovery is automatic (§158/§89)
#   R3 Two scheduler instances     -> exactly ONE holds the Prompt 22
#                                   lease (§129/§162)
#   R4 Production config gate      -> API refuses to boot with a
#                                   placeholder secret (§30/§33)
# Requires the stack from start.sh. Prints PASS/FAIL per item.
set -u
STACK="$HOME/workspace/dsrclone-local-stack"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
B="http://127.0.0.1:4000/api/v1"
PASS=0; FAIL=0
ok()  { if [ "$1" = 0 ]; then echo "PASS  $2"; PASS=$((PASS+1)); else echo "FAIL  $2"; FAIL=$((FAIL+1)); fi }

echo "== R1: API kill + restart keeps persisted state"
BEFORE=$(curl -s "$B/health" | python3 -c "import json,sys; print(json.load(sys.stdin)['checks']['postgres']['status'])" 2>/dev/null)
pkill -f "apps/api/dist/main.js"; sleep 2
setsid nohup env $(grep -v '^#' "$STACK/smoke.env" | xargs) node "$REPO/apps/api/dist/main.js" >> "$STACK/api.log" 2>&1 < /dev/null &
for i in $(seq 1 20); do curl -sf "$B/health/live" >/dev/null 2>&1 && break; sleep 1; done
AFTER=$(curl -s "$B/health" | python3 -c "import json,sys; print(json.load(sys.stdin)['checks']['postgres']['status'])" 2>/dev/null)
[ "$BEFORE" = "ok" ] && [ "$AFTER" = "ok" ]; ok $? "R1 api restarted, postgres state intact"

echo "== R2: Redis pause — live stays up, ready drops, then recovers"
RPID=$(pgrep -f "redis-server 127.0.0.1:6379" | head -1)
LIVE_BEFORE=$(curl -s -o /dev/null -w "%{http_code}" "$B/health/live")
kill -STOP "$RPID" 2>/dev/null; sleep 3
LIVE_DURING=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$B/health/live")
READY_DURING=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$B/health/ready")
kill -CONT "$RPID" 2>/dev/null; sleep 3
READY_AFTER=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$B/health/ready")
echo "   live before=$LIVE_BEFORE during=$LIVE_DURING | ready during=$READY_DURING after=$READY_AFTER"
[ "$LIVE_BEFORE" = 200 ] && [ "$LIVE_DURING" = 200 ] && [ "$READY_DURING" = 503 ] && [ "$READY_AFTER" = 200 ]
ok $? "R2 liveness independent of Redis; readiness tracks it and recovers"

echo "== R3: scheduler lease — exactly one active control plane"
ENVV=$(grep -v '^#' "$STACK/smoke.env" | xargs)
setsid nohup env $ENVV SCHEDULER_TICK_MS=3000 SCHEDULER_OWNER_ID=sched-A node "$REPO/apps/api/dist/scheduler-main.js" > "$STACK/sched-a.log" 2>&1 < /dev/null &
sleep 6
setsid nohup env $ENVV SCHEDULER_TICK_MS=3000 SCHEDULER_OWNER_ID=sched-B node "$REPO/apps/api/dist/scheduler-main.js" > "$STACK/sched-b.log" 2>&1 < /dev/null &
sleep 8
A_ACQ=$(grep -c '"acquired":true' "$STACK/sched-a.log" || true)
B_ACQ=$(grep -c '"acquired":true' "$STACK/sched-b.log" || true)
B_HELD=$(grep -c '"acquired":false' "$STACK/sched-b.log" || true)
echo "   sched-A acquired ticks=$A_ACQ | sched-B acquired=$B_ACQ held-by-other=$B_HELD"
pkill -f "scheduler-main.js"; sleep 1
[ "$A_ACQ" -ge 1 ] && [ "$B_ACQ" = 0 ] && [ "$B_HELD" -ge 1 ]
ok $? "R3 standby scheduler never acquires the lease while the primary lives"

echo "== R4: production config gate refuses placeholder secrets"
WEAK_SECRET=$(python3 -c "print('change-me-' + 'x' * 30)")
OUT=$(env NODE_ENV=production JWT_SECRET="$WEAK_SECRET" DATABASE_URL="postgresql://dsrclone:placeholder-pw@127.0.0.1:54329/dsrclone" REDIS_URL="redis://127.0.0.1:6379" timeout 10 node "$REPO/apps/api/dist/main.js" 2>&1 || true)
echo "$OUT" | grep -q "Refusing to start in production mode"
ok $? "R4 API refuses to boot in production mode with placeholder secret"

echo
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
