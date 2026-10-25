#!/usr/bin/env bash
# Quick local health check for all ZeroSweep services.
set -u
API_PORT="${API_PORT:-4000}"
AI_PORT="${AI_PORT:-8000}"
WEB_PORT="${WEB_PORT:-3000}"
echo "API    : $(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${API_PORT}/api/v1/health" || echo unreachable)"
echo "AI     : $(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${AI_PORT}/health" || echo unreachable)"
echo "Web    : $(curl -s -o /dev/null -w '%{http_code}' "http://localhost:${WEB_PORT}/" || echo unreachable)"
if [ -f "${WORKER_HEARTBEAT_FILE:-/tmp/dsrclone-worker-heartbeat.json}" ]; then
  echo "Worker : heartbeat present (${WORKER_HEARTBEAT_FILE:-/tmp/dsrclone-worker-heartbeat.json})"
else
  echo "Worker : no heartbeat file (worker not running, or WORKER_HEARTBEAT_FILE differs)"
fi
