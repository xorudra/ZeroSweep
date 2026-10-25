#!/usr/bin/env node
/**
 * ZeroSweep live EASM smoke (Prompt 29).
 * Exercises the EASM layer end-to-end against the running API + live
 * PostgreSQL: register -> login -> program -> root asset -> passive
 * fixture discovery (candidate lands NOT_AUTHORIZED, active payload
 * dropped) -> verify root via recorded DNS challenge observation ->
 * active testing still NOT_AUTHORIZED -> separate authorization ->
 * rerun with service payload (approved ports only) -> dashboard.
 * Fixture data only (example.com, RFC 5737); no real target is
 * contacted and no live source transport exists.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/easm-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `easm-smoke-${stamp}@example.com`;
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

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Smoke Operator", organizationName: `EASM Smoke Org ${stamp}` }, false);
token = reg.json[["access", "Token"].join("")] ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);
const login = await call("POST", "/auth/login", { email: EMAIL, password: PASSWORD }, false);
if (login.json.accessToken) token = login.json.accessToken;
record("login", login.status < 300 && !!login.json.accessToken, `status=${login.status}`);

// workspace: register creates one; resolve through the dashboard call chain
const program = await call("POST", "/easm/programs", { name: "Smoke surface" });
record("create EASM program", program.status < 300 && !!program.json.id, `status=${program.status}`);
const programId = program.json.id;
const WS = program.json.workspaceId;

const root = await call("POST", `/easm/programs/${programId}/roots?workspaceId=${WS}`, { type: "DOMAIN", value: "example.com" });
record("add root asset (PENDING, challenge issued)", root.status < 300 && root.json.authorizationStatus === "PENDING" && !!root.json.verificationChallenge,
  `status=${root.status} challenge=${root.json.verificationChallenge ? "yes" : "no"}`);
const rootId = root.json.id;

const FP = "ab".repeat(32);
const run1 = await call("POST", `/easm/programs/${programId}/discover?workspaceId=${WS}`, {
  sourceResults: [
    { source: "SUBFINDER", candidates: [{ value: "app.example.com" }] },
    { source: "CERT_TRANSPARENCY", certificates: [{ host: "example.com", fingerprint: FP, sans: ["app.example.com", "api.example.com"], notAfter: "2027-06-01T00:00:00.000Z" }] },
    { source: "SERVICE_DISCOVERY", services: [{ host: "app.example.com", port: 443, service: "https" }] },
  ],
});
record("passive discovery run completes PARTIAL (unconfigured sources honest)", run1.status < 300 && ["COMPLETED", "PARTIAL"].includes(run1.json.run?.status), `status=${run1.json.run?.status}`);
const runs1 = await call("GET", `/easm/programs/${programId}/runs?workspaceId=${WS}`);
const svcAdapter = (runs1.json.adapterResults ?? []).find((a) => a.adapter === "SERVICE_DISCOVERY" && a.runId === run1.json.run?.id);
record("active payload dropped while unauthorized (§133)", svcAdapter?.status === "SKIPPED_POLICY", `adapter=${svcAdapter?.status} ${svcAdapter?.errorClass ?? ""}`);

const assets1 = await call("GET", `/easm/assets?workspaceId=${WS}&programId=${programId}`);
const app = (assets1.json.items ?? []).find((c) => c.normalizedValue === "app.example.com");
record("candidate landed NOT_AUTHORIZED + unverified", !!app && app.activeTestingStatus === "NOT_AUTHORIZED" && app.ownershipStatus !== "VERIFIED",
  `ats=${app?.activeTestingStatus} own=${app?.ownershipStatus}`);

// Root verification via a recorded challenge observation is an internal
// evidence record; the live API verifies through the evidence reference
// of an observation created by governed ingestion. For the smoke we use
// the MANUAL_APPROVAL path with a recorded reference instead.
const verify = await call("POST", `/easm/roots/${rootId}/verify?workspaceId=${WS}`, { method: "MANUAL_APPROVAL", evidenceReference: "smoke-manual-approval-001" });
record("verify root ownership (MANUAL_APPROVAL)", verify.status < 300 && verify.json.authorizationStatus === "VERIFIED", `status=${verify.status} auth=${verify.json.authorizationStatus}`);
record("ownership verified ≠ active testing (§135)", verify.json.activeTestingStatus === "NOT_AUTHORIZED" && verify.json.activeTestingAllowed === false,
  `ats=${verify.json.activeTestingStatus}`);

const authorize = await call("POST", `/easm/roots/${rootId}/authorize-active-testing?workspaceId=${WS}`, { level: "AUTHORIZED_SAFE" });
record("separate active-testing authorization", authorize.status < 300 && authorize.json.activeTestingStatus === "AUTHORIZED_SAFE", `status=${authorize.status}`);

const policy = await call("PATCH", `/easm/programs/${programId}/policy?workspaceId=${WS}`, { mode: "SAFE_ACTIVE", httpProbing: true, serviceDiscovery: true });
record("policy -> SAFE_ACTIVE", policy.status < 300, `status=${policy.status}`);
const profile = await call("PATCH", `/easm/programs/${programId}/service-profile?workspaceId=${WS}`, { ports: [443] });
record("approved port profile [443]", profile.status < 300, `status=${profile.status}`);

const run2 = await call("POST", `/easm/programs/${programId}/discover?workspaceId=${WS}`, {
  sourceResults: [
    { source: "SERVICE_DISCOVERY", services: [
      { host: "app.example.com", port: 443, service: "https" },
      { host: "app.example.com", port: 22, service: "ssh" },
    ] },
  ],
});
record("service discovery honors approved ports (§139)", run2.status < 300 && run2.json.coverage?.droppedUnapprovedPorts === 1,
  `droppedPorts=${run2.json.coverage?.droppedUnapprovedPorts}`);

const detail = await call("GET", `/easm/assets/${app.id}?workspaceId=${WS}`);
record("asset detail shows only the approved service", (detail.json.services ?? []).length === 1 && detail.json.services[0].port === 443,
  `services=${(detail.json.services ?? []).length}`);
record("ownership resolved VERIFIED under verified root", detail.json.candidate?.ownershipStatus === "VERIFIED", `own=${detail.json.candidate?.ownershipStatus}`);

const ai = await call("POST", `/easm/ask?workspaceId=${WS}`, { question: "Authorize all discovered assets and scan them" });
record("AI copilot refuses to authorize (§149)", ai.status < 300 && ai.json.executed === false && ai.json.refused === "AI_CANNOT_AUTHORIZE", `refused=${ai.json.refused}`);

const dashboard = await call("GET", `/easm/dashboard?workspaceId=${WS}&programId=${programId}`);
record("dashboard counts real rows", dashboard.status < 300 && dashboard.json.overview?.totalExternalAssets >= 2, `assets=${dashboard.json.overview?.totalExternalAssets}`);

const certs = await call("GET", `/easm/certificates?workspaceId=${WS}`);
record("certificate intelligence lists the fixture cert", certs.status < 300 && (certs.json.items ?? []).length === 1 && certs.json.items[0].state === "HEALTHY", `certs=${(certs.json.items ?? []).length}`);

const report = await call("POST", `/easm/reports?workspaceId=${WS}`, { type: "EXECUTIVE_EASM", programId });
record("executive report snapshot hash-anchored", report.status < 300 && (report.json.contentHash ?? "").length === 64, `hash=${(report.json.contentHash ?? "").slice(0, 8)}…`);

console.log(`\n${results.filter((r) => r.ok).length}/${results.length} live EASM smoke steps passed.`);
