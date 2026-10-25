// Launch Safety Standard G34 — load test for the ZeroSweep API.
//
// RUN ONLY AGAINST LOCAL OR STAGING. NEVER PRODUCTION. The script
// hard-refuses the production API host so a mistyped BASE_URL cannot
// turn this into a production load test.
//
// Usage:
//   k6 run scripts/load/k6-load.js
//   BASE_URL=http://localhost:4000 k6 run scripts/load/k6-load.js
//   BASE_URL=https://<staging-api-host> k6 run scripts/load/k6-load.js
//
// Optional authenticated read (a workspace-scoped list endpoint):
//   API_TOKEN=<jwt for a staging/local test account> k6 run ...
//
// What to record after a run (in the G/H audit notes): the ramp stage
// where thresholds first failed (the observed breaking point), which
// threshold broke, and what saturated first (API CPU, DB connections,
// Redis) per the /api/v1/metrics output and host metrics.
import http from "k6/http";
import { check, sleep } from "k6";
import { Rate } from "k6/metrics";

const BASE_URL = (__ENV.BASE_URL || "http://localhost:4000").replace(/\/$/, "");
const PRODUCTION_HOSTS = ["dsrclone-api.onrender.com", "dsrclone-web.onrender.com"];

if (PRODUCTION_HOSTS.some((h) => BASE_URL.includes(h))) {
  throw new Error(
    `Refusing to load-test production (${BASE_URL}). ` +
      "Point BASE_URL at a local or staging deployment instead (item G34)."
  );
}

const errors = new Rate("errors");

export const options = {
  stages: [
    { duration: "30s", target: 10 }, // warm ramp
    { duration: "1m", target: 10 }, // hold — baseline behaviour
    { duration: "30s", target: 25 }, // push
    { duration: "1m", target: 25 }, // hold at push — watch for first break
    { duration: "30s", target: 50 }, // spike probe
    { duration: "30s", target: 0 }, // drain
  ],
  thresholds: {
    // Item G34: failed requests < 1%; stated p95 budget for the cheap
    // read paths exercised here (health + one tenant list read).
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<800"],
    errors: ["rate<0.01"],
  },
};

export default function () {
  // Public, unauthenticated read paths (cheap, no tenant data).
  const health = http.get(`${BASE_URL}/api/v1/health`);
  check(health, { "health 200": (r) => r.status === 200 }) || errors.add(1);

  const live = http.get(`${BASE_URL}/api/v1/health/live`);
  check(live, { "live 200": (r) => r.status === 200 }) || errors.add(1);

  // Authenticated tenant read — only when a token for a LOCAL/STAGING
  // test account is supplied; skipped silently otherwise. The token is
  // never logged.
  if (__ENV.API_TOKEN) {
    const res = http.get(`${BASE_URL}/api/v1/findings?page=1&pageSize=20`, {
      headers: { Authorization: `Bearer ${__ENV.API_TOKEN}` },
    });
    check(res, { "findings list 200": (r) => r.status === 200 }) || errors.add(1);
  }

  sleep(1);
}
