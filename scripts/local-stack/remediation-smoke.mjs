#!/usr/bin/env node
/**
 * DSRclone Prompt 31 live remediation smoke.
 * Runs the REAL governed flow against the running stack: register ->
 * target -> verify -> scope -> assessment -> approve -> scan (fixture
 * domain example.com, simulation adapters only) -> take a persisted
 * finding -> remediation case -> SLA policy + assignment -> triage ->
 * assign -> in-progress -> fix claim -> MANUAL_EVIDENCE_REVIEW
 * verification -> VERIFIED_FIXED -> closure -> finding RESOLVED.
 * Nothing here can force a state: every step goes through the same
 * guarded API an operator uses.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/remediation-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `remsmoke-${stamp}@example.com`;
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

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Remediation Smoke", organizationName: `Rem Smoke Org ${stamp}` }, false);
token = reg.json.accessToken ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);

const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
record("create target", target.status < 300 && !!target.json.id, `status=${target.status}`);
const ver = await call("POST", `/targets/${target.json.id}/verifications`, { method: "MANUAL_APPROVAL" });
const check = await call("POST", `/targets/${target.json.id}/verifications/${ver.json.verification?.id}/check`, {});
record("verify target", check.status < 300, `status=${check.status}`);
const scope = await call("POST", "/scopes", { targetId: target.json.id, name: "example.com only", rules: { includeHosts: ["example.com"] } });
const assessment = await call("POST", "/assessments", { name: "Rem Smoke PASSIVE_RECON", targetId: target.json.id, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
const approve = await call("POST", `/assessments/${assessment.json.id}/approve`, {});
record("approve assessment", approve.status < 300, `status=${approve.status}`);
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
const finding = (vulns.json.items ?? []).find((f) => !f.duplicateOfId) ?? (vulns.json.items ?? [])[0];
record("finding available", !!finding?.id, `count=${(vulns.json.items ?? []).length} severity=${finding?.severity} lifecycle=${finding?.lifecycleStatus}`);
if (!finding?.id) { console.log(`\n${results.filter((r) => r.ok).length}/${results.length} passed`); process.exit(1); }

// --- Prompt 31 flow ---
const created = await call("POST", `/remediation/findings/${finding.id}/case`, {});
const kase = created.json.case;
record("case ensured", created.status < 300 && !!kase?.id, `status=${created.status} caseStatus=${kase?.status} slaAssigned=${created.json.slaAssigned}`);

const policy = await call("POST", "/remediation/sla/policies", { name: "Smoke SLA", isDefault: true, rules: { P0: 24, P1: 72, P2: 168, P3: 336, P4: 720, INFORMATIONAL: 720, LOW: 336, MEDIUM: 168, HIGH: 72, CRITICAL: 24 } });
record("SLA policy created", policy.status < 300 && !!policy.json.id, `status=${policy.status} version=${policy.json.version}`);
const slaAssign = await call("POST", `/remediation/${kase.id}/sla/assign`, {});
record("SLA assigned with snapshot", slaAssign.status < 300 && !!slaAssign.json.snapshot?.dueAt, `dueAt=${slaAssign.json.snapshot?.dueAt} policyVersion=${slaAssign.json.snapshot?.policyVersion}`);

const triage = await call("POST", `/remediation/${kase.id}/triage`, { decision: "ACTION_REQUIRED", reason: "smoke: real work" });
record("triage", triage.status < 300 && triage.json.case?.status === "TRIAGED", `status=${triage.status} caseStatus=${triage.json.case?.status}`);
const assign = await call("POST", `/remediation/${kase.id}/assign`, { ownerType: "TEAM", teamId: "team-smoke", reason: "smoke assignment" });
record("assign", assign.status < 300 && assign.json.case?.status === "ASSIGNED", `status=${assign.status} caseStatus=${assign.json.case?.status}`);
const progress = await call("PATCH", `/remediation/${kase.id}`, { to: "IN_PROGRESS", reason: "smoke: work started" });
record("in progress", progress.status < 300 && progress.json.status === "IN_PROGRESS", `status=${progress.status}`);
const claim = await call("POST", `/remediation/${kase.id}/fix-claim`, { claimSource: "MANUAL", description: "smoke: configuration corrected on the fixture target" });
record("fix claimed (not verified)", claim.status < 300 && claim.json.case?.status === "FIX_CLAIMED", `status=${claim.status} caseStatus=${claim.json.case?.status}`);
const verifyReq = await call("POST", `/remediation/${kase.id}/verify`, { method: "MANUAL_EVIDENCE_REVIEW" });
const job = verifyReq.json.job;
record("verification requested", verifyReq.status < 300 && !!job?.id, `status=${verifyReq.status} jobStatus=${job?.status}`);
const observation = await call("POST", `/remediation/${kase.id}/verification/${job.id}/observation`, {
  scannerStatus: "OK", stillPresent: false, evidenceSufficient: true,
  tool: "smoke-manual-review", beforeObservation: { note: "issue present at detection" },
  afterObservation: { note: "issue absent on manual re-check of the fixture target" },
});
record("verification passed -> VERIFIED_FIXED", observation.status < 300 && observation.json.case?.status === "VERIFIED_FIXED",
  `status=${observation.status} outcome=${observation.json.evaluation?.outcome} caseStatus=${observation.json.case?.status}`);
const detail = await call("GET", `/remediation/${kase.id}`);
record("finding lifecycle RESOLVED", detail.json.finding?.lifecycleStatus === "RESOLVED", `lifecycle=${detail.json.finding?.lifecycleStatus}`);
const close = await call("POST", `/remediation/${kase.id}/close`, { reason: "smoke: verified fixed" });
record("closure", close.status < 300 && close.json.case?.status === "CLOSED", `status=${close.status} caseStatus=${close.json.case?.status}`);
const dash = await call("GET", "/remediation/dashboard");
record("dashboard reflects closure", dash.status < 300 && (dash.json.closed ?? 0) >= 1, `closed=${dash.json.closed} verifiedFixed=${dash.json.verifiedFixed}`);

console.log(`\n${results.filter((r) => r.ok).length}/${results.length} remediation smoke steps passed`);
