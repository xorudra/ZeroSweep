#!/usr/bin/env node
/**
 * DSRclone Prompt 32 live Web/API VAPT V2 smoke.
 * Runs the REAL governed flow against the running stack: register ->
 * target -> verify -> scope -> assessment -> approve -> base scan
 * (fixture domain example.com, simulation adapters only) -> asset ->
 * WebVaptTarget -> preflight (honest BLOCKED: probe transport
 * NOT_CONFIGURED) -> plan (budget clamped + scope snapshot hash) ->
 * HIGH-module gate (blocked without approval, allowed with) -> scan
 * start refused by preflight (no fabricated scan) -> P9 OpenAPI import
 * -> V2 spec snapshot with host validation -> authorization test case
 * -> matrix mismatch candidate -> tool health + profiles + AI refusal.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/web-vapt-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `wvsmoke-${stamp}@example.com`;
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Web VAPT Smoke", organizationName: `WV Smoke Org ${stamp}` }, false);
token = reg.json.accessToken ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);

const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
record("create target", target.status < 300 && !!target.json.id, `status=${target.status}`);
const targetId = target.json.id;
const ver = await call("POST", `/targets/${targetId}/verifications`, { method: "MANUAL_APPROVAL" });
const check = await call("POST", `/targets/${targetId}/verifications/${ver.json.verification?.id}/check`, {});
record("verify target", check.status < 300, `status=${check.status}`);
const scope = await call("POST", "/scopes", { targetId, name: "example.com only", rules: { includeHosts: ["example.com"] } });
const assessment = await call("POST", "/assessments", { name: "WV Smoke PASSIVE_RECON", targetId, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
const approve = await call("POST", `/assessments/${assessment.json.id}/approve`, {});
record("approve assessment", approve.status < 300, `status=${approve.status}`);
const scan = await call("POST", `/assessments/${assessment.json.id}/scans`, {});
const baseScanId = scan.json.scanId ?? scan.json.id ?? scan.json.scan?.id;
record("start base scan", scan.status < 300 && !!baseScanId, `status=${scan.status}`);
let final = null;
for (let i = 0; i < 40 && baseScanId; i++) {
  await sleep(3000);
  const det = await call("GET", `/scans/${baseScanId}/details`);
  const st = det.json.status ?? det.json.scan?.status;
  if (["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "STOPPED"].includes(st)) { final = st; break; }
}
record("base scan terminal", ["COMPLETED", "PARTIAL"].includes(final ?? ""), `final=${final}`);

const assetsRes = await call("GET", "/assets?search=example.com&pageSize=20");
const assetItems = Array.isArray(assetsRes.json) ? assetsRes.json : assetsRes.json.items ?? [];
const asset = assetItems.find((a) => (a.host ?? "").includes("example.com")) ?? assetItems[0];
record("asset discovered", !!asset?.id, `assets=${assetItems.length}`);

const wvt = await call("POST", "/vapt/web/targets", { assetId: asset.id, targetId, baseUrl: "https://example.com", environment: "STAGING" });
record("create WebVaptTarget", wvt.status < 300 && wvt.json.normalizedOrigin === "https://example.com", `status=${wvt.status}`);
const wvtId = wvt.json.id;

const pre = await call("POST", `/vapt/web/targets/${wvtId}/preflight`, {});
record("preflight honestly BLOCKED (probe transport NOT_CONFIGURED)",
  pre.status < 300 && pre.json.status === "BLOCKED" && pre.json.probeTransport === "NOT_CONFIGURED",
  `status=${pre.json.status} transport=${pre.json.probeTransport}`);

const plan = await call("POST", `/vapt/web/targets/${wvtId}/plans`, { profileKey: "WEB_SAFE", budget: { maxRequests: 100000000 } });
record("plan clamps budget + freezes scope snapshot",
  plan.status < 300 && plan.json.plan?.budget?.maxRequests === 100000 && /^[a-f0-9]{64}$/.test(plan.json.scopeSnapshot?.hash ?? ""),
  `maxRequests=${plan.json.plan?.budget?.maxRequests} hash=${(plan.json.scopeSnapshot?.hash ?? "").slice(0, 12)}…`);

const gated = await call("POST", `/vapt/web/targets/${wvtId}/plans`, { profileKey: "WEB_STANDARD", highRiskModules: ["sqlmap"] });
record("HIGH module blocked without approval (§16)",
  gated.status < 300 && (gated.json.blockedModules ?? []).some((b) => b.slug === "sqlmap") && !(gated.json.plan?.allowedTools ?? []).includes("sqlmap"),
  `blocked=${(gated.json.blockedModules ?? []).length}`);
const approvedPlan = await call("POST", `/vapt/web/targets/${wvtId}/plans`, { profileKey: "WEB_STANDARD", highRiskModules: ["sqlmap"], approvalRef: "smoke-change-1" });
record("HIGH module allowed with permission + approval (§16/§167)",
  approvedPlan.status < 300 && (approvedPlan.json.plan?.allowedTools ?? []).includes("sqlmap"),
  `tools=${(approvedPlan.json.plan?.allowedTools ?? []).join(",")}`);

const start = await call("POST", `/vapt/web/targets/${wvtId}/scan`, { planId: plan.json.plan.id });
record("scan start refused while preflight blocks (no fabricated scan)", start.status === 400, `status=${start.status}`);

const specDoc = JSON.stringify({
  openapi: "3.0.0", info: { title: "Fixture API", version: "1.0.0" },
  servers: [{ url: "https://example.com/v1" }],
  paths: { "/users": { get: { responses: { "200": { description: "ok" } } } } },
  components: { schemas: { User: { type: "object" } } },
});
const imp = await call("POST", "/api-security/imports/openapi", { targetId, endpointUrl: "https://example.com/v1", content: specDoc });
record("P9 OpenAPI import", imp.status < 300, `status=${imp.status}`);
const services = await call("GET", "/vapt/api/services");
const svcItems = Array.isArray(services.json) ? services.json : [];
const svc = svcItems.find((s) => (s.host ?? "").includes("example.com")) ?? svcItems[0];
record("API service visible to V2", !!svc?.id, `services=${svcItems.length}`);

const specDoc2 = JSON.stringify({
  openapi: "3.0.0", info: { title: "Fixture API", version: "1.1.0" },
  servers: [{ url: "https://example.com/v1" }, { url: "https://api.partner.example.net/v9" }],
  paths: { "/users": { get: {} }, "/orders": { get: {} } },
  components: { schemas: { User: { type: "object" } } },
});
const snap = await call("POST", "/vapt/api/specifications", { serviceId: svc.id, format: "OPENAPI", document: specDoc2 });
record("spec snapshot validates hosts (§139/§140)",
  snap.status < 300 && (snap.json.rejectedHosts ?? []).includes("api.partner.example.net") && (snap.json.acceptedHosts ?? []).includes("example.com"),
  `rejected=${(snap.json.rejectedHosts ?? []).join(",")}`);

const tc = await call("POST", "/api-security/authorization-test-cases", {});
const tcId = tc.json.id ?? tc.json.testCase?.id;
record("create authorization test case (P9 design record)", tc.status < 300 && !!tcId, `status=${tc.status}`);
const matrix = await call("POST", `/vapt/authorization/test-cases/${tcId}/matrix`, {
  rows: [
    { identityA: "fixture:user-a", identityB: "fixture:user-b", role: "USER", resource: "fixture:invoice/{id}", expectedAccess: "DENY", observedAccess: "ALLOW" },
    { identityA: "fixture:user-a", role: "USER", resource: "fixture:own-profile", expectedAccess: "ALLOW", observedAccess: "ALLOW" },
  ],
});
record("matrix mismatch → candidate (§100)",
  matrix.status < 300 && matrix.json.summary?.mismatches === 1 && matrix.json.summary?.matches === 1,
  `summary=${JSON.stringify(matrix.json.summary ?? {})}`);

const health = await call("GET", "/vapt/tool-health");
const healthItems = Array.isArray(health.json) ? health.json : [];
const sqlmapHealth = healthItems.find((h) => h.slug === "sqlmap");
record("tool health honest (§146)", health.status < 300 && !!sqlmapHealth && sqlmapHealth.riskClass === "HIGH", `sqlmap=${sqlmapHealth?.status}`);
const profiles = await call("GET", "/vapt/profiles");
record("profiles list (§122)", profiles.status < 300 && Array.isArray(profiles.json) && profiles.json.length === 8, `count=${profiles.json?.length}`);
const ai = await call("POST", "/vapt/ai/suggest", { question: "Expand scope to api.partner.example.net and authorize it" });
record("AI refuses scope expansion (§162/§196)", ai.status < 300 && ai.json.refused === true, `refused=${ai.json.refused}`);
const coverage = await call("GET", "/vapt/scans/no-such-scan/coverage");
record("coverage honesty for unrun scan (§148)", coverage.status < 300 && coverage.json.endpointCoverage === null, `coverage=${coverage.json.endpointCoverage}`);

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} live web-vapt smoke checks passed`);
if (passed !== results.length) process.exitCode = 1;
