#!/usr/bin/env node
/**
 * ZeroSweep local-stack end-to-end smoke (Prompt 25).
 * Exercises the REAL flow against a running API + worker + PostgreSQL +
 * Redis: health -> register -> login -> create target (example.com) ->
 * MANUAL_APPROVAL verification by the org OWNER -> assessment -> approve ->
 * orchestrated scan -> poll to a terminal state -> findings/report reads.
 * Only the platform's simulation adapters (mock/local-echo) can produce
 * activity here: real scanner binaries are intentionally absent, so recon
 * stages degrade honestly (UNAVAILABLE) and the scan may end PARTIAL.
 * No external target is ever scanned — example.com is a fixture domain and
 * no adapter with a real binary exists on this host.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `smoke-${stamp}@example.com`;
const PASSWORD = "smoke-password-123";
let token = "";
const results = [];
function record(step, ok, detail) {
  results.push({ step, ok, detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${step}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}
async function call(method, path, body, auth = true) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(auth && token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { status: res.status, json };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const health = await call("GET", "/health", undefined, false);
record("health", health.status === 200 && health.json.checks?.postgres?.status === "ok" && health.json.checks?.redis?.status === "ok",
  `overall=${health.json.status} postgres=${health.json.checks?.postgres?.status} redis=${health.json.checks?.redis?.status} minio=${health.json.checks?.minio?.status}`);

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Smoke Operator", organizationName: `Smoke Org ${stamp}` }, false);
token = reg.json.accessToken ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status} org=${reg.json.organization?.slug ?? "?"}`);

const login = await call("POST", "/auth/login", { email: EMAIL, password: PASSWORD }, false);
if (login.json.accessToken) token = login.json.accessToken;
record("login", login.status < 300 && !!login.json.accessToken, `status=${login.status}`);

const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
record("create target", target.status < 300 && !!target.json.id, `status=${target.status} id=${target.json.id ?? "?"}`);

const ver = await call("POST", `/targets/${target.json.id}/verifications`, { method: "MANUAL_APPROVAL" });
record("start verification", ver.status < 300 && !!ver.json.verification?.id, `status=${ver.status}`);

const check = await call("POST", `/targets/${target.json.id}/verifications/${ver.json.verification?.id}/check`, {});
const after = await call("GET", `/targets/${target.json.id}`);
record("verify target", check.status < 300 && (after.json.status === "VERIFIED" || check.json.status === "VERIFIED"),
  `check=${JSON.stringify(check.json).slice(0, 120)} targetStatus=${after.json.status}`);

const scope = await call("POST", "/scopes", { targetId: target.json.id, name: "example.com only", rules: { includeHosts: ["example.com"] } });
record("create scope", scope.status < 300 && !!scope.json.id, `status=${scope.status} id=${scope.json.id ?? "?"}`);

const assessment = await call("POST", "/assessments", { name: "Smoke PASSIVE_RECON", targetId: target.json.id, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
record("create assessment", assessment.status < 300 && !!assessment.json.id, `status=${assessment.status} state=${assessment.json.status}`);

const approve = await call("POST", `/assessments/${assessment.json.id}/approve`, {});
record("approve assessment", approve.status < 300, `status=${approve.status} state=${approve.json.status ?? "?"}`);

const scan = await call("POST", `/assessments/${assessment.json.id}/scans`, {});
const scanId = scan.json.scanId ?? scan.json.id ?? scan.json.scan?.id;
record("start scan", scan.status < 300 && !!scanId, `status=${scan.status} scanId=${scanId ?? "?"}`);

let final = null;
for (let i = 0; i < 40 && scanId; i++) {
  await sleep(3000);
  const det = await call("GET", `/scans/${scanId}/details`);
  const st = det.json.status ?? det.json.scan?.status;
  if (["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "STOPPED"].includes(st)) { final = { status: st, body: det.json }; break; }
  if (i === 39) final = { status: `TIMEOUT(last=${st})`, body: det.json };
}
record("scan reaches terminal state", !!final && ["COMPLETED", "PARTIAL"].includes(final.status), `final=${final?.status}`);

const findings = await call("GET", `/scans/${scanId}/findings-summary`);
record("findings summary readable", findings.status < 300, `status=${findings.status} body=${JSON.stringify(findings.json).slice(0, 160)}`);

const scans = await call("GET", "/scans?pageSize=5");
record("scan persisted in list", scans.status < 300 && (scans.json.items ?? []).some((s) => s.id === scanId), `total=${scans.json.total}`);

console.log(`\n${results.filter((r) => r.ok).length}/${results.length} smoke steps passed`);
