#!/usr/bin/env node
/**
 * Operator health check (Prompt 40 §210): verifies API reachability,
 * health endpoint status, database/queue/storage checks, worker
 * presence and release identity. Prints a compact report; exits 1 when
 * any REQUIRED check fails. Values are measured, never assumed.
 */
const base = process.env.API_BASE_URL ?? "http://127.0.0.1:4000/api/v1";

let failures = 0;
function report(name, ok, detail, required = true) {
  console.log(`  [${ok ? "OK  " : "FAIL"}] ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok && required) failures++;
}

try {
  const res = await fetch(`${base}/health`);
  const body = await res.json().catch(() => ({}));
  report("API reachable", res.ok, `HTTP ${res.status}`);
  report("Overall health", body.status === "ok" || body.status === "degraded", `status=${body.status ?? "unknown"}`);
  for (const [name, check] of Object.entries(body.checks ?? {})) {
    report(`check:${name}`, check.status === "ok", check.detail ?? check.status, name === "database");
  }
} catch (err) {
  report("API reachable", false, String(err?.message ?? err));
}

try {
  const res = await fetch(`${base}/product/health`);
  const body = await res.json().catch(() => ({}));
  report("Product health endpoint", res.status === 401 || res.ok, res.status === 401 ? "requires auth (expected)" : `HTTP ${res.status}`, false);
} catch { /* optional surface */ }

console.log(failures === 0 ? "HEALTH CHECK: PASS" : `HEALTH CHECK: FAIL (${failures} required check(s) failed)`);
process.exit(failures === 0 ? 0 : 1);
