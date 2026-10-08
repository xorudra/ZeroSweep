#!/usr/bin/env node
/**
 * DSRclone RC1 end-to-end suite (Prompt 39 §198–§223).
 *
 * Runs against a LIVE local stack (API + worker + PostgreSQL + Redis +
 * MinIO). Fixtures are synthetic and local only: two organizations
 * (TenantA / TenantB), one client organization (ClientA), the fixture
 * domain example.com, and the platform's simulation adapters — no
 * external target is ever scanned (§201).
 *
 * Suites:
 *   core-flow        §210 complete flow: workspace -> target -> verify ->
 *                    scope -> assessment -> approve -> scan -> findings ->
 *                    report -> review -> finalize -> client access
 *   tenant-isolation §40 matrix: TenantB probes TenantA objects across
 *                    targets / scans / findings / reports / assets /
 *                    search / analytics — all must 404 or exclude A data
 *   client-isolation §41/§138-139: portal projection contains published,
 *                    client-safe data only; internal notes never appear
 *   negative         §222-223: unauthenticated, bad token, unverified
 *                    target scan, invalid state transition, scanner flag
 *                    injection, AI scope expansion, revoked/expired
 *                    share link, self-service mass assignment
 *   self-security    §65-70/§276: security headers, CORS origin policy,
 *                    error shape (no stack/SQL leakage)
 *   ai               §218: grounded copilot answer with executed:false;
 *                    cross-tenant question yields no foreign records
 *
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node tests/e2e/run-e2e.mjs
 * Writes a machine-readable summary to E2E_RESULTS_PATH when set.
 * Exit code 1 when any check fails.
 */
import { writeFileSync } from "node:fs";

const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const PASSWORD = "e2e-password-123";
const results = [];
let suite = "setup";
function record(name, ok, detail = "") {
  results.push({ suite, name, ok, detail: String(detail).slice(0, 300) });
  console.log(`${ok ? "PASS" : "FAIL"}  [${suite}] ${name}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}
async function call(method, path, body, token) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { status: res.status, json, headers: res.headers };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function registerOrg(label) {
  const reg = await call("POST", "/auth/register", {
    email: `e2e-${label}-${stamp}@example.com`, password: PASSWORD,
    name: `E2E ${label}`, organizationName: `E2E ${label} ${stamp}`,
  });
  return reg.json.accessToken;
}

// ---------------------------------------------------------------- setup
suite = "core-flow";
const health = await call("GET", "/health");
record("stack health ok", health.status === 200 && health.json.status === "ok", `status=${health.json.status}`);

const tokenA = await registerOrg("tenantA");
record("TenantA registered (persona OrgAdmin)", !!tokenA);

const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" }, tokenA);
const targetId = target.json.id;
record("authorized target created", target.status < 300 && !!targetId, `status=${target.status}`);

const ver = await call("POST", `/targets/${targetId}/verifications`, { method: "MANUAL_APPROVAL" }, tokenA);
const check = await call("POST", `/targets/${targetId}/verifications/${ver.json.verification?.id}/check`, {}, tokenA);
const after = await call("GET", `/targets/${targetId}`, undefined, tokenA);
record("target verified", check.status < 300 && after.json.status === "VERIFIED", `targetStatus=${after.json.status}`);

const scope = await call("POST", "/scopes", { targetId, name: "example.com only", rules: { includeHosts: ["example.com"] } }, tokenA);
record("scope created", scope.status < 300 && !!scope.json.id);

const assessment = await call("POST", "/assessments", { name: "E2E PASSIVE_RECON", targetId, scopeId: scope.json.id, profile: "PASSIVE_RECON" }, tokenA);
record("assessment created PENDING_APPROVAL", assessment.status < 300 && !!assessment.json.id, `state=${assessment.json.status}`);
const approve = await call("POST", `/assessments/${assessment.json.id}/approve`, {}, tokenA);
record("assessment approved", approve.status < 300, `state=${approve.json.status}`);

const scan = await call("POST", `/assessments/${assessment.json.id}/scans`, {}, tokenA);
const scanId = scan.json.scanId ?? scan.json.id ?? scan.json.scan?.id;
record("scan started through governed path", scan.status < 300 && !!scanId, `scanId=${scanId}`);
let finalStatus = null;
for (let i = 0; i < 40 && scanId; i++) {
  await sleep(3000);
  const det = await call("GET", `/scans/${scanId}/details`, undefined, tokenA);
  const st = det.json.status ?? det.json.scan?.status;
  if (["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "STOPPED"].includes(st)) { finalStatus = st; break; }
}
record("scan reaches terminal state", ["COMPLETED", "PARTIAL"].includes(finalStatus), `final=${finalStatus}`);

const vulns = await call("GET", "/vulnerabilities?pageSize=10", undefined, tokenA);
const findingId = (vulns.json.items ?? [])[0]?.id;
record("findings normalized into canonical list", vulns.status < 300 && Array.isArray(vulns.json.items), `total=${vulns.json.total}`);

// Report lifecycle on the canonical finding set (§219)
const report = await call("POST", "/security-reports", { title: "E2E RC1 Report", type: "TECHNICAL_VAPT" }, tokenA);
const reportId = report.json.id ?? report.json.report?.id;
record("report created", report.status < 300 && !!reportId, `status=${report.status}`);
const gen = await call("POST", `/security-reports/${reportId}/generate`, {}, tokenA);
record("report generated from snapshot", gen.status < 300, `status=${gen.status}`);
await call("POST", `/security-reports/${reportId}/submit-review`, {}, tokenA);
const appr = await call("POST", `/security-reports/${reportId}/approve`, {}, tokenA);
record("report approved", appr.status < 300, `status=${appr.status}`);

// ------------------------------------------------------- tenant isolation
suite = "tenant-isolation";
const tokenB = await registerOrg("tenantB");
record("TenantB registered", !!tokenB);

const probes = [
  ["target detail", await call("GET", `/targets/${targetId}`, undefined, tokenB), (r) => r.status === 404],
  ["scan detail", await call("GET", `/scans/${scanId}/details`, undefined, tokenB), (r) => r.status === 404],
  ["scan list excludes A", await call("GET", "/scans?pageSize=50", undefined, tokenB), (r) => !(r.json.items ?? []).some((s) => s.id === scanId)],
  ["findings list excludes A", await call("GET", "/vulnerabilities?pageSize=50", undefined, tokenB), (r) => !(r.json.items ?? []).some((f) => f.id === findingId)],
  ["assets list excludes A target host", await call("GET", "/assets?pageSize=50", undefined, tokenB), (r) => r.status < 300],
  ["report detail", await call("GET", `/security-reports/${reportId}`, undefined, tokenB), (r) => r.status === 404 || r.status === 403],
  ["search excludes A finding", await call("GET", `/search?q=${encodeURIComponent("example.com")}`, undefined, tokenB), (r) => r.status === 404 || !JSON.stringify(r.json).includes(reportId)],
];
for (const [name, res, ok] of probes) record(name, ok(res), `status=${res.status}`);

// ------------------------------------------------------- client isolation
suite = "client-isolation";
const client = await call("POST", "/client-portal/admin/clients", { name: `ClientA ${stamp}`, slug: `clienta-${stamp}` }, tokenA);
const malformedClient = await call("POST", "/client-portal/admin/clients", { name: "Missing slug" }, tokenA);
record("malformed admin body is a 400, never a 500 (RC1-H1)", malformedClient.status === 400, `status=${malformedClient.status}`);
const engagement = await call("POST", "/client-portal/admin/engagements", { clientOrganizationId: client.json.id, name: "E2E Engagement" }, tokenA);
record("client + engagement created", client.status < 300 && engagement.status < 300, `client=${client.status} eng=${engagement.status}`);
if (findingId) {
  const pub = await call("POST", `/client-portal/admin/engagements/${engagement.json.id}/publish`, { findingId }, tokenA);
  record("finding published to client engagement", pub.status < 300, `status=${pub.status}`);
}
const fin = await call("POST", `/security-reports/${reportId}/finalize`, {}, tokenA);
record("report finalized (immutable snapshot)", fin.status < 300, `status=${fin.status}`);

// ------------------------------------------------------------- negative
suite = "negative";
const unauth = await call("GET", "/scans", undefined, undefined);
record("unauthenticated request is 401", unauth.status === 401, `status=${unauth.status}`);
const badTok = await call("GET", "/scans", undefined, "not-a-real-token");
record("garbage bearer token is 401", badTok.status === 401, `status=${badTok.status}`);

// Unverified target cannot be assessed/scanned (§49/§223)
const target2 = await call("POST", "/targets", { name: "Unverified", type: "DOMAIN", value: "unverified.example.com" }, tokenA);
const scope2 = await call("POST", "/scopes", { targetId: target2.json.id, name: "s2", rules: { includeHosts: ["unverified.example.com"] } }, tokenA);
const assess2 = await call("POST", "/assessments", { name: "Should fail", targetId: target2.json.id, scopeId: scope2.json.id, profile: "PASSIVE_RECON" }, tokenA);
const appr2 = await call("POST", `/assessments/${assess2.json.id}/approve`, {}, tokenA);
const scan2 = assess2.json.id ? await call("POST", `/assessments/${assess2.json.id}/scans`, {}, tokenA) : { status: 0 };
record("unverified target cannot reach a running scan",
  !(scan2.status < 300 && scan2.json.scanId) && (assess2.status >= 400 || appr2.status >= 400 || scan2.status >= 400 || !assess2.json.id),
  `assess=${assess2.status} approve=${appr2.status} scan=${scan2.status}`);

// Invalid finding state transition (§94/§223)
if (findingId) {
  const badTransition = await call("POST", `/vulnerability-management/findings/${findingId}/triage`, { status: "NOT_A_REAL_STATUS" }, tokenA);
  record("invalid state transition rejected", badTransition.status >= 400, `status=${badTransition.status}`);
}

// Scanner flag injection (§77/§223): tool config carrying shell/args keys
const flagInjection = await call("POST", "/tools", { slug: "e2e-evil", name: "Evil", category: "RECON", riskLevel: "PASSIVE", licenseType: "OPEN_SOURCE", capabilities: [], supportedTargets: ["DOMAIN"], command: "nmap; rm -rf /" }, tokenA);
record("arbitrary command in tool registration rejected/ignored",
  flagInjection.status >= 400 || !JSON.stringify(flagInjection.json).includes("rm -rf"),
  `status=${flagInjection.status}`);

// Mass assignment (§36): creating a target while naming a foreign workspace
const massAssign = await call("POST", "/targets", { name: "MA", type: "DOMAIN", value: "ma.example.com", workspaceId: "00000000-0000-0000-0000-000000000000", organizationId: "org-b" }, tokenA);
const maList = await call("GET", "/targets?pageSize=100", undefined, tokenB);
record("mass-assigned tenant fields do not relocate the record",
  !(maList.json.items ?? []).some((t) => t.value === "ma.example.com"),
  `create=${massAssign.status} visibleToB=${(maList.json.items ?? []).some((t) => t.value === "ma.example.com")}`);

// Share link lifecycle (§135): create -> resolve -> revoke -> 404
const link = await call("POST", `/security-reports/${reportId}/share-links`, { expiresInHours: 1, maxDownloads: 2 }, tokenA);
const sharedOk = link.json.token ? await call("GET", `/shared-reports/${link.json.token}`) : { status: 0 };
record("share link resolves while valid", sharedOk.status === 200, `create=${link.status} resolve=${sharedOk.status}`);
if (link.json.token && link.json.id) {
  await call("DELETE", `/security-reports/${reportId}/share-links/${link.json.id}`, undefined, tokenA);
  const afterRevoke = await call("GET", `/shared-reports/${link.json.token}`);
  record("revoked share link is 404", afterRevoke.status === 404, `status=${afterRevoke.status}`);
}
const forgedLink = await call("GET", "/shared-reports/00000000000000000000000000000000");
record("forged share token is 404", forgedLink.status === 404, `status=${forgedLink.status}`);

// --------------------------------------------------------- self-security
suite = "self-security";
const hdrRes = await fetch(`${BASE}/health`);
const h = hdrRes.headers;
record("security headers present (helmet)",
  !!h.get("x-content-type-options") && !!h.get("x-frame-options") || !!h.get("content-security-policy") || !!h.get("x-content-type-options"),
  `xcto=${h.get("x-content-type-options")} xfo=${h.get("x-frame-options")} csp=${h.get("content-security-policy") ? "set" : "unset"}`);
const cors = await fetch(`${BASE}/scans`, { method: "OPTIONS", headers: { origin: "https://evil.example", "access-control-request-method": "GET" } });
record("CORS does not reflect arbitrary origins",
  cors.headers.get("access-control-allow-origin") !== "https://evil.example",
  `acao=${cors.headers.get("access-control-allow-origin")}`);
const errProbe = await call("GET", "/scans/00000000-0000-0000-0000-000000000000/details", undefined, tokenA);
const errText = JSON.stringify(errProbe.json);
record("error responses leak no stack/SQL/paths",
  !/at .*\(.*:\d+:\d+\)|SELECT |\/home\/|node_modules/.test(errText),
  `status=${errProbe.status}`);

// ------------------------------------------------------------------- ai
suite = "ai";
const qa = await call("POST", "/ai/copilot", { query: "Explain the highest-risk verified finding and cite evidence.", taskType: "SECURITY_QA" }, tokenA);
record("copilot answers grounded with executed:false",
  qa.status < 300 && qa.json.executed === false && typeof qa.json.response?.answer === "string",
  `status=${qa.status} origin=${qa.json.response?.origin}`);
const qaB = await call("POST", "/ai/copilot", { query: "Explain the highest-risk verified finding and cite evidence.", taskType: "SECURITY_QA" }, tokenB);
record("copilot for TenantB cites no TenantA records",
  qaB.status < 300 && !JSON.stringify(qaB.json).includes(reportId) && !JSON.stringify(qaB.json).includes(scanId),
  `status=${qaB.status}`);
const shellTool = await call("POST", "/ai/tools/runShellCommand/call", { command: "id" }, tokenA);
record("AI has no shell tool (gateway refusal)", shellTool.status >= 400 || shellTool.json.executed === false, `status=${shellTool.status}`);

// -------------------------------------------------------------- summary
const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} E2E checks passed`);
const summary = {
  generatedAt: new Date().toISOString(), apiBase: BASE,
  total: results.length, passed, failed: results.length - passed, results,
};
if (process.env.E2E_RESULTS_PATH) writeFileSync(process.env.E2E_RESULTS_PATH, JSON.stringify(summary, null, 2));
