#!/usr/bin/env node
/**
 * DSRclone live SOC smoke (Prompt 28).
 * Exercises the SOC layer end-to-end against the running API + live
 * PostgreSQL: register -> login -> telemetry source -> seed + activate
 * a detection template -> ingest fixture auth-failure telemetry ->
 * deduped alert -> re-ingest (duplicates only) -> STIX fixture import
 * -> indicator match -> escalate to incident -> timeline note ->
 * governed response action (propose + execute) -> dashboard.
 * Fixture data only (example domains, RFC 5737 addresses); no real
 * target is contacted and no live intel transport exists.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/soc-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `soc-smoke-${stamp}@example.com`;
const PASSWORD = "smoke-password-123";
let token = "";
const results = [];
function record(step, ok, detail) {
  results.push({ step, ok });
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

const health = await call("GET", "/health", undefined, false);
record("health (postgres ok, minio provisioned)", health.status === 200 && health.json.checks?.postgres?.status === "ok" && health.json.checks?.minio?.status === "ok",
  `postgres=${health.json.checks?.postgres?.status} minio=${health.json.checks?.minio?.status}`);

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Smoke Operator", organizationName: `SOC Smoke Org ${stamp}` }, false);
token = reg.json[["access", "Token"].join("")] ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);
const login = await call("POST", "/auth/login", { email: EMAIL, password: PASSWORD }, false);
if (login.json.accessToken) token = login.json.accessToken;
record("login", login.status < 300 && !!login.json.accessToken, `status=${login.status}`);

const source = await call("POST", "/soc/telemetry/sources", { name: "okta-fixture", sourceCategory: "AUTHENTICATION", expectedIntervalSeconds: 300 });
record("create telemetry source", source.status < 300 && !!source.json.id, `status=${source.status}`);

const seeded = await call("POST", "/soc/detections/seed-templates", {});
const rules = await call("GET", "/soc/detections");
const burst = (rules.json.items ?? []).find((r) => r.templateKey === "auth-failure-burst");
record("seed detection templates", seeded.status < 300 && !!burst, `rules=${(rules.json.items ?? []).length}`);

const toTesting = await call("POST", `/soc/detections/${burst.id}/status`, { status: "TESTING" });
const toActive = await call("POST", `/soc/detections/${burst.id}/status`, { status: "ACTIVE" });
record("promote rule DRAFT -> TESTING -> ACTIVE", toTesting.status < 300 && toActive.status < 300 && toActive.json.status === "ACTIVE", `status=${toActive.json.status}`);

const now = Date.now();
const failEvents = [0, 1, 2, 3, 4].map((i) => ({
  id: `smoke-fail-${stamp}-${i}`, source: "okta-fixture", sourceCategory: "AUTHENTICATION",
  eventCategory: "AUTHENTICATION", eventAction: "LOGIN",
  eventTime: new Date(now - (4 - i) * 30000).toISOString(),
  identityReference: "rudra", attributes: { outcome: "FAILURE" },
}));
const ingestBody = { auth: { kind: "USER_SESSION", reference: "smoke-session" }, events: failEvents };
const ingested = await call("POST", "/soc/telemetry/ingest", ingestBody);
record("ingest 5 fixture auth failures -> detection + alert",
  ingested.status < 300 && ingested.json.stored === 5 && ingested.json.alertsCreated >= 1,
  `stored=${ingested.json.stored} matches=${ingested.json.detectionMatches} alerts=${ingested.json.alertsCreated}`);

const alerts = await call("GET", "/soc/alerts");
const alert = (alerts.json.items ?? [])[0];
record("alert queue holds exactly one deduped alert", (alerts.json.items ?? []).length === 1 && !!alert, `alerts=${(alerts.json.items ?? []).length}`);

const replay = await call("POST", "/soc/telemetry/ingest", ingestBody);
record("re-ingest is idempotent (duplicates only, no new alert)",
  replay.status < 300 && replay.json.duplicates === 5 && replay.json.alertsCreated === 0,
  `duplicates=${replay.json.duplicates} alerts=${replay.json.alertsCreated}`);

const intelSource = await call("POST", "/soc/intel-sources", { name: "Recorded fixture feed", type: "FIXTURE", trustLevel: 90 });
record("intel source registered NOT_CONFIGURED (honest)", intelSource.status < 300 && intelSource.json.transportStatus === "NOT_CONFIGURED", `transport=${intelSource.json.transportStatus}`);

const stix = {
  type: "bundle", id: "bundle--smoke",
  objects: [{ type: "indicator", id: "indicator--smoke", pattern: "[domain-name:value = 'evil.example']", valid_from: "2026-10-01T00:00:00Z" }],
};
const imported = await call("POST", `/soc/intel-sources/${intelSource.json.id}/import`, { format: "STIX", bundle: stix });
record("STIX fixture import", imported.status < 300 && imported.json.created === 1, `created=${imported.json.created}`);

const dns = await call("POST", "/soc/telemetry/ingest", {
  auth: { kind: "USER_SESSION", reference: "smoke-session" },
  events: [{ id: `smoke-dns-${stamp}`, source: "dns-fixture", sourceCategory: "DNS", eventCategory: "DNS", eventAction: "QUERY", eventTime: new Date().toISOString(), attributes: { domain: "evil.example" } }],
});
record("DNS event matches the imported indicator", dns.status < 300 && dns.json.indicatorMatches >= 1, `matches=${dns.json.indicatorMatches}`);

const incident = await call("POST", `/soc/alerts/${alert.id}/escalate`, {});
record("escalate alert to incident", incident.status < 300 && !!incident.json.id, `incident=${incident.json.id ?? "?"}`);

const note = await call("POST", `/soc/incidents/${incident.json.id}/timeline`, { summary: "Smoke: analyst triage note." });
record("append timeline note", note.status < 300, `status=${note.status}`);

const proposed = await call("POST", `/soc/incidents/${incident.json.id}/actions`, {
  actionKey: "SEND_NOTIFICATION", targetReference: incident.json.id, nonce: `smoke-${stamp}`,
});
record("propose NO_APPROVAL response action", proposed.status < 300 && proposed.json.execution?.status === "APPROVED", `status=${proposed.json.execution?.status}`);
const executed = await call("POST", `/soc/response-actions/${proposed.json.execution.id}/execute`, {});
record("execute response action", executed.status < 300 && executed.json.executed === true, `executed=${executed.json.executed}`);

const dashboard = await call("GET", "/soc/dashboard");
record("SOC dashboard reflects the recorded operations",
  dashboard.status < 300 && dashboard.json.overview?.indicatorMatches >= 1 && dashboard.json.overview?.activeIncidents >= 1,
  `openAlerts=${dashboard.json.overview?.openAlerts} incidents=${dashboard.json.overview?.activeIncidents} matches=${dashboard.json.overview?.indicatorMatches}`);

const passed = results.filter((r) => r.ok).length;
console.log(`\nSOC SMOKE: ${passed}/${results.length} PASS`);
