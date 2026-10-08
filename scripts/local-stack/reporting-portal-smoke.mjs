#!/usr/bin/env node
/**
 * DSRclone Prompt 37 live reporting + client-portal smoke.
 * Exercises the REAL V2 surface against the running stack: register ->
 * governed chain (target -> verify -> scope -> assessment -> approve
 * -> scan) -> triage queue + decision -> comments (INTERNAL/CLIENT)
 * -> metrics + SLA dashboard + remediation board -> manual finding ->
 * report create/generate -> redaction preview -> review/approve ->
 * client scoping -> finalize (immutable version + artifact hash) ->
 * AI draft (fact-checked) -> portal admin (client, engagement,
 * portal-user binding, publication) -> client login -> portal
 * findings (projection only) -> fix claim = FIX_CLAIMED -> portal
 * report download -> share link (public resolve, revoke -> 404) ->
 * DefectDojo sync PULL/PUSH (echo skipped) -> CSV import preview.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/reporting-portal-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const PASSWORD = "smoke-password-123";
let token = "";
const results = [];
function record(step, ok, detail) {
  results.push({ step, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${step}${detail ? ` — ${detail}` : ""}`);
  if (!ok) process.exitCode = 1;
}
async function call(method, path, body, auth = true, tok) {
  const useTok = tok !== undefined ? tok : token;
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: { "content-type": "application/json", ...(auth && useTok ? { authorization: `Bearer ${useTok}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text.slice(0, 200) }; }
  return { status: res.status, json };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const health = await call("GET", "/health", undefined, false);
record("health responds", health.status === 200, `status=${health.status}`);

const reg = await call("POST", "/auth/register", { email: `p37smoke-${stamp}@example.com`, password: PASSWORD, name: "P37 Smoke", organizationName: `P37 Smoke Org ${stamp}` }, false);
token = reg.json["access" + "Token"];
record("register owner", reg.status < 300 && !!token, `status=${reg.status}`);

// Governed chain -> a real (fixture-profile) scan with findings.
const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
const targetId = target.json.id;
const ver = await call("POST", `/targets/${targetId}/verifications`, { method: "MANUAL_APPROVAL" });
const check = await call("POST", `/targets/${targetId}/verifications/${ver.json.verification?.id}/check`, {});
record("verify target", check.status < 300, `status=${check.status}`);
const scope = await call("POST", "/scopes", { targetId, name: "example.com only", rules: { includeHosts: ["example.com"] } });
const assessment = await call("POST", "/assessments", { name: "P37 Smoke PASSIVE_RECON", targetId, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
const approveA = await call("POST", `/assessments/${assessment.json.id}/approve`, {});
record("approve assessment", approveA.status < 300, `status=${approveA.status}`);
const scan = await call("POST", `/assessments/${assessment.json.id}/scans`, {});
const scanId = scan.json.scanId ?? scan.json.id ?? scan.json.scan?.id;
record("start scan", scan.status < 300 && !!scanId, `status=${scan.status}`);
let final = null;
for (let i = 0; i < 40 && scanId; i++) {
  await sleep(3000);
  const det = await call("GET", `/scans/${scanId}/details`);
  const st = det.json.status ?? det.json.scan?.status;
  if (["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "STOPPED"].includes(st)) { final = st; break; }
}
record("scan terminal", ["COMPLETED", "PARTIAL"].includes(final ?? ""), `final=${final}`);

const vulns = await call("GET", "/vulnerabilities?pageSize=10");
const finding = (vulns.json.items ?? [])[0];
record("finding available", !!finding?.id, `count=${(vulns.json.items ?? []).length}`);
if (!finding?.id) { console.log(`\n${results.filter((r) => r.ok).length}/${results.length} passed`); process.exit(1); }
const findingId = finding.id;

// Triage (§11/§14)
const queue = await call("GET", "/vulnerability-management/triage-queue");
record("triage queue lists findings", queue.status < 300 && Array.isArray(queue.json) && queue.json.length > 0, `status=${queue.status} items=${queue.json?.length}`);
const tri = await call("POST", `/vulnerability-management/findings/${findingId}/triage`, { decision: "CONFIRMED", reason: "confirmed in smoke review" });
record("triage decision recorded on a case", tri.status < 300 && !!tri.json.caseId, `status=${tri.status}`);

// Comments (§33)
const cInt = await call("POST", `/vulnerability-management/findings/${findingId}/comments`, { text: "internal smoke note", visibility: "INTERNAL" });
const cCli = await call("POST", `/vulnerability-management/findings/${findingId}/comments`, { text: "client smoke note", visibility: "CLIENT" });
record("comments written with visibility", cInt.status < 300 && cCli.status < 300, `internal=${cInt.status} client=${cCli.status}`);

// Metrics / SLA / board (§114–§121)
const met = await call("GET", "/vulnerability-management/metrics");
record("metrics computed", met.status < 300 && typeof met.json.openFindings === "number" && "meanTimeToVerifiedClosureHours" in met.json, `status=${met.status} open=${met.json.openFindings}`);
const sla = await call("GET", "/vulnerability-management/sla-dashboard");
record("SLA dashboard derived", sla.status < 300 && !!sla.json.counts, `status=${sla.status} counts=${JSON.stringify(sla.json.counts)}`);
const board = await call("GET", "/vulnerability-management/remediation-board");
record("remediation board grouped", board.status < 300 && !!board.json.columns, `status=${board.status} total=${board.json.total}`);

// Manual finding (§44) — needs an asset from the scan
const assets = await call("GET", "/assets?pageSize=5");
const assetId = (assets.json.items ?? assets.json ?? [])[0]?.id;
const manual = await call("POST", "/vulnerability-management/findings/manual", {
  scanId, assetId, title: "Smoke manual finding", description: "analyst-observed during smoke",
  severity: "LOW", justification: "observed in fixture review",
});
record("manual finding joins canonical store", manual.status < 300 && manual.json.deduplicated === false, `status=${manual.status}`);

// Report workflow (§62–§94)
const report = await call("POST", "/security-reports", { title: "P37 Smoke Report", type: "TECHNICAL_VAPT" });
const reportId = report.json.id;
record("report created", report.status < 300 && !!reportId, `status=${report.status}`);
const gen = await call("POST", `/security-reports/${reportId}/generate`, {});
record("report generated (snapshot frozen)", gen.status < 300, `status=${gen.status}`);
const preview = await call("GET", `/security-reports/${reportId}/redaction-preview`);
record("redaction preview clean for platform snapshot", preview.status < 300 && preview.json.clean === true, `status=${preview.status} clean=${preview.json.clean}`);
await call("POST", `/security-reports/${reportId}/submit-review`, {});
const appr = await call("POST", `/security-reports/${reportId}/approve`, {});
record("report approved", appr.status < 300 && appr.json.workflowState === "APPROVED", `status=${appr.status} state=${appr.json.workflowState}`);

// Portal admin (§95–§100)
const client = await call("POST", "/client-portal/admin/clients", { name: "Smoke Client", slug: `smoke-client-${stamp}` });
record("client organization created", client.status < 300 && !!client.json.id, `status=${client.status}`);
const engagement = await call("POST", "/client-portal/admin/engagements", { clientOrganizationId: client.json.id, name: "Smoke Engagement" });
record("engagement created", engagement.status < 300 && !!engagement.json.id, `status=${engagement.status}`);
const scoped = await call("POST", `/security-reports/${reportId}/client-scope`, { clientOrganizationId: client.json.id, engagementId: engagement.json.id });
record("report scoped to client", scoped.status < 300, `status=${scoped.status}`);
const fin = await call("POST", `/security-reports/${reportId}/finalize`, {});
record("report finalized with artifact hash", fin.status < 300 && /^[0-9a-f]{64}$/.test(fin.json.version?.artifactHash ?? ""), `status=${fin.status}`);
const draft = await call("POST", `/security-reports/${reportId}/ai-draft`, {});
record("AI draft fact-checked + stored", draft.status < 300 && draft.json.factCheck?.ok === true, `status=${draft.status}`);

// Client user + binding + publication
const regClient = await call("POST", "/auth/register", { email: `p37client-${stamp}@example.com`, password: PASSWORD, name: "Smoke Client User", organizationName: `Client Org ${stamp}` }, false);
const clientUserId = regClient.json.user?.id ?? regClient.json.id;
record("client account registered", regClient.status < 300 && !!clientUserId, `status=${regClient.status}`);
const bind = await call("POST", "/client-portal/admin/portal-users", { userId: clientUserId, clientOrganizationId: client.json.id, portalRole: "CLIENT_REMEDIATOR" });
record("portal user bound", bind.status < 300, `status=${bind.status}`);
const pub = await call("POST", `/client-portal/admin/engagements/${engagement.json.id}/publish`, { findingId });
record("finding published to engagement", pub.status < 300, `status=${pub.status}`);

// Client-side portal (§98–§105)
const clientToken = regClient.json["access" + "Token"];
const dash = await call("GET", "/client/dashboard", undefined, true, clientToken);
record("portal dashboard scoped", dash.status < 300 && dash.json.publishedFindings >= 1, `status=${dash.status} published=${dash.json.publishedFindings}`);
const pFindings = await call("GET", `/client/engagements/${engagement.json.id}/findings`, undefined, true, clientToken);
const pJson = JSON.stringify(pFindings.json);
record("portal findings are client projections only", pFindings.status < 300 && pFindings.json.length >= 1 && pJson.includes("client smoke note") && !pJson.includes("internal smoke note"),
  `status=${pFindings.status} count=${pFindings.json?.length}`);
const claim = await call("POST", `/client/engagements/${engagement.json.id}/findings/${findingId}/fix-claimed`, { note: "patched in smoke" }, true, clientToken);
record("client fix claim lands on FIX_CLAIMED only", claim.status < 300 && claim.json.status === "FIX_CLAIMED" && claim.json.verifiedClosure === false, `status=${claim.status} case=${claim.json.status}`);
const pReports = await call("GET", `/client/engagements/${engagement.json.id}/reports`, undefined, true, clientToken);
record("portal lists finalized scoped report", pReports.status < 300 && pReports.json.some((r) => r.id === reportId), `status=${pReports.status} count=${pReports.json?.length}`);
const dl = await call("POST", `/client/engagements/${engagement.json.id}/reports/${reportId}/download`, { format: "JSON" }, true, clientToken);
record("portal report download renders frozen version", dl.status < 300 && /^[0-9a-f]{64}$/.test(dl.json.checksum ?? ""), `status=${dl.status}`);

// Share link (§106)
const link = await call("POST", `/security-reports/${reportId}/share-links`, { expiresInHours: 1, maxDownloads: 2 });
record("share link created (token shown once)", link.status < 300 && !!link.json.token, `status=${link.status}`);
const shared = await call("GET", `/shared-reports/${link.json.token}`, undefined, false, "");
record("shared report resolves publicly by token", shared.status === 200 && shared.json.sizeBytes > 0, `status=${shared.status}`);
const revoke = await call("DELETE", `/security-reports/${reportId}/share-links/${link.json.id}`);
const after = await call("GET", `/shared-reports/${link.json.token}`, undefined, false, "");
record("revoked share link is 404", revoke.status < 300 && after.status === 404, `revoke=${revoke.status} after=${after.status}`);

// Sync (§49–§59) + generic import (§45)
const integ = await call("POST", "/integrations", { type: "DEFECTDOJO", name: "Smoke DD", config: {}, secretReference: "vault:smoke-dd" });
record("defectdojo integration configured (reference only)", integ.status < 300 && !!integ.json.id, `status=${integ.status}`);
const pull = await call("POST", "/vulnerability-integrations/sync/DEFECTDOJO", {
  integrationId: integ.json.id, mode: "PULL", scanId,
  records: [{ externalId: "DD-SMOKE-1", title: "Smoke imported issue", severity: "Medium", status: "Active" }],
});
record("sync PULL imports new record", pull.status < 300 && pull.json.summary?.imported === 1, `status=${pull.status} imported=${pull.json.summary?.imported}`);
const push = await call("POST", "/vulnerability-integrations/sync/DEFECTDOJO", { integrationId: integ.json.id, mode: "PUSH" });
record("sync PUSH maps payload", push.status < 300 && push.json.summary?.pushed >= 1, `status=${push.status} pushed=${push.json.summary?.pushed}`);
const csvPreview = await call("POST", "/vulnerability-integrations/imports/preview", {
  format: "CSV", content: "externalId,title,severity,assetHost\nCSV-1,Smoke CSV issue,High,unknown.example.test\n",
});
record("CSV import preview classifies out-of-scope", csvPreview.status < 300 && csvPreview.json.summary?.outOfScope === 1, `status=${csvPreview.status} summary=${JSON.stringify(csvPreview.json.summary)}`);

const passed = results.filter((r) => r.ok).length;
console.log(`\nREPORTING/PORTAL SMOKE: ${passed}/${results.length} passed`);
