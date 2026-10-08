#!/usr/bin/env node
/**
 * DSRclone Prompt 33 live Network VAPT V2 smoke.
 * Runs the REAL governed flow against the running stack: register ->
 * target -> verify -> scope -> assessment -> approve -> base scan
 * (fixture domain example.com, simulation adapters only) -> asset ->
 * NetworkVaptTarget (RFC 5737 CIDR) -> injection + huge-CIDR refusals
 * -> preflight (honest TOOL_UNAVAILABLE: probe transport
 * NOT_CONFIGURED) -> plan (budget clamped + snapshot hash + Masscan
 * gate + brute-NSE blocked in the open) -> scan start refused (no
 * fabricated scan) -> discovery candidate (out-of-scope host is never
 * scannable) -> hosts + tool health (Metasploit NOT_PROVISIONED) ->
 * packet capture bounds (§151 reject + governed record) -> segment +
 * baseline + drift (§153 ELEVATED) -> Metasploit payload request
 * BLOCKED (§149) -> exploit references EMPTY (§148) -> AI refusal
 * (§157). Fixture data only; nothing is scanned.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/network-vapt-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `nvsmoke-${stamp}@example.com`;
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

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Network VAPT Smoke", organizationName: `NV Smoke Org ${stamp}` }, false);
token = reg.json.accessToken ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);

const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
record("create target", target.status < 300 && !!target.json.id, `status=${target.status}`);
const targetId = target.json.id;
const ver = await call("POST", `/targets/${targetId}/verifications`, { method: "MANUAL_APPROVAL" });
const check = await call("POST", `/targets/${targetId}/verifications/${ver.json.verification?.id}/check`, {});
record("verify target", check.status < 300, `status=${check.status}`);
const scope = await call("POST", "/scopes", { targetId, name: "example.com only", rules: { includeHosts: ["example.com"] } });
const assessment = await call("POST", "/assessments", { name: "NV Smoke PASSIVE_RECON", targetId, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
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

const nvt = await call("POST", "/vapt/network/targets", { assetId: asset.id, targetId, targetType: "CIDR", targetValue: "203.0.113.0/24", environment: "PRODUCTION", criticality: "HIGH" });
record("create NetworkVaptTarget (RFC 5737 /24)", nvt.status < 300 && nvt.json.targetValue === "203.0.113.0/24", `status=${nvt.status}`);
const nvtId = nvt.json.id;

const inject = await call("POST", "/vapt/network/targets", { assetId: asset.id, targetId, targetType: "IP", targetValue: "192.0.2.10; rm -rf /" });
record("§138 target injection refused", inject.status === 400, `status=${inject.status}`);
const huge = await call("POST", "/vapt/network/targets", { assetId: asset.id, targetId, targetType: "CIDR", targetValue: "10.0.0.0/8", internalEngagementApproved: true });
record("§140 huge CIDR refused", huge.status === 400, `status=${huge.status}`);

const pre = await call("POST", `/vapt/network/targets/${nvtId}/preflight`, {});
record("preflight honestly TOOL_UNAVAILABLE (probe transport NOT_CONFIGURED)",
  pre.status < 300 && pre.json.status === "TOOL_UNAVAILABLE" && pre.json.probeTransport === "NOT_CONFIGURED",
  `status=${pre.json.status} transport=${pre.json.probeTransport}`);

const plan = await call("POST", `/vapt/network/targets/${nvtId}/plans`, { profileKey: "NETWORK_SAFE", budget: { maxHosts: 100000000 } });
record("plan clamps budget + freezes scope snapshot (§17/§18/§11)",
  plan.status < 300 && plan.json.plan?.budget?.maxHosts === 4096 && /^[a-f0-9]{64}$/.test(plan.json.scopeSnapshot?.hash ?? ""),
  `maxHosts=${plan.json.plan?.budget?.maxHosts} hash=${(plan.json.scopeSnapshot?.hash ?? "").slice(0, 12)}…`);

const gatedPlan = await call("POST", `/vapt/network/targets/${nvtId}/plans`, {
  profileKey: "NETWORK_VULNERABILITY", masscanRequested: true, masscanRate: 5000000, platformPermissionRef: "platform-policy-1",
  nseScripts: ["ssh-brute", "banner"],
});
const blockedItems = gatedPlan.json.blockedItems ?? [];
record("§139 Masscan excessive rate → MASSCAN_NOT_APPROVED on the plan",
  gatedPlan.status < 300 && blockedItems.some((b) => (b.reason ?? "").includes("MASSCAN_NOT_APPROVED")) && !(gatedPlan.json.plan?.tools ?? []).includes("masscan"),
  `blocked=${blockedItems.length}`);
record("§142 brute NSE blocked on the plan in the open",
  blockedItems.some((b) => b.item === "NSE:ssh-brute") && (gatedPlan.json.plan?.scriptsUsed ?? []).some((s) => s.id === "banner"),
  `scripts=${(gatedPlan.json.plan?.scriptsUsed ?? []).map((s) => s.id).join(",")}`);

const start = await call("POST", `/vapt/network/targets/${nvtId}/scan`, { planId: plan.json.plan.id });
record("scan start refused while preflight is not READY (no fabricated scan)", start.status === 400, `status=${start.status}`);

const discovery = await call("POST", "/vapt/network/discoveries", { ip: "10.0.0.20", snapshotCidrs: ["10.0.0.0/28"], discoveryMethod: "ARP_SCAN" });
record("§141 out-of-scope discovery → CANDIDATE, never scannable",
  discovery.status < 300 && discovery.json.decision?.scannable === false && discovery.json.observation?.scopeStatus === "CANDIDATE",
  `scope=${discovery.json.observation?.scopeStatus}`);

const hosts = await call("GET", "/vapt/network/hosts");
record("hosts view (§114)", hosts.status < 300 && Array.isArray(hosts.json) && hosts.json.length >= 1, `hosts=${hosts.json?.length}`);

const health = await call("GET", "/vapt/network/tool-health");
const healthItems = Array.isArray(health.json) ? health.json : [];
record("tool health honest (§120)",
  health.status < 300 && healthItems.find((h) => h.slug === "metasploit")?.status === "NOT_PROVISIONED"
    && ["UNKNOWN", "NOT_CONFIGURED", "UNAVAILABLE", "DISABLED"].includes(healthItems.find((h) => h.slug === "nmap")?.status ?? ""),
  `tools=${healthItems.length} nmap=${healthItems.find((h) => h.slug === "nmap")?.status}`);

const oversized = await call("POST", "/vapt/network/packet-captures", { interfaceReference: "worker-1/eth0", interfaceAuthorized: true, durationSeconds: 999999, sizeLimitBytes: 1000 });
record("§151 oversized packet capture rejected", oversized.status === 400, `status=${oversized.status}`);
const capture = await call("POST", "/vapt/network/packet-captures", { interfaceReference: "worker-1/eth0", interfaceAuthorized: true, durationSeconds: 300, sizeLimitBytes: 1000000 });
record("packet capture recorded with bounds, transport NOT_CONFIGURED (§84/§85)",
  capture.status < 300 && capture.json.status === "REQUESTED" && capture.json.transport === "NOT_CONFIGURED",
  `status=${capture.json.status}`);

const segment = await call("POST", "/vapt/network/segments", { name: "docs-range", cidr: "203.0.113.0/24", zone: "INTERNET", criticality: "HIGH" });
record("segment create (§95)", segment.status < 300 && !!segment.json.id, `status=${segment.status}`);
const baseline = await call("POST", "/vapt/network/baselines", { hosts: [
  { host: "192.0.2.30", criticality: "CRITICAL", environment: "PRODUCTION", services: [
    { port: 22, transport: "tcp", service: "ssh", version: "8.9p1" },
    { port: 443, transport: "tcp", service: "https", version: "1.25.3", tls: true },
  ], vulnerabilities: [] },
] });
record("baseline v1 frozen (§104)", baseline.status < 300 && baseline.json.version === 1, `version=${baseline.json.version}`);
const drift = await call("POST", "/vapt/network/drift/compute", { hosts: [
  { host: "192.0.2.30", criticality: "CRITICAL", environment: "PRODUCTION", services: [
    { port: 22, transport: "tcp", service: "ssh", version: "8.9p1" },
    { port: 443, transport: "tcp", service: "https", version: "1.25.3", tls: true },
    { port: 3389, transport: "tcp", service: "ms-wbt-server" },
  ], vulnerabilities: [] },
] });
const driftEvents = drift.json.events ?? [];
record("§153 drift: new RDP on critical host → SERVICE_ADDED + ELEVATED",
  drift.status < 300 && driftEvents.some((e) => e.kind === "SERVICE_ADDED" && e.riskSignal === "ELEVATED"),
  `events=${driftEvents.length}`);

const ms = await call("POST", "/vapt/network/metasploit-verifications", {
  moduleId: "exploit/windows/smb/ms17_010_eternalblue", host: "203.0.113.10", findingId: "f-1",
  payloadRequested: "windows/meterpreter/reverse_tcp", hostAuthorized: true,
});
record("§149 Metasploit payload request BLOCKED", ms.status < 300 && ms.json.verdict?.decision === "BLOCKED", `decision=${ms.json.verdict?.decision}`);

const refs = await call("GET", "/vapt/network/exploit-references?cve=CVE-2021-41773");
record("§148 exploit references honestly EMPTY", refs.status < 300 && refs.json.datasetState === "EMPTY" && (refs.json.references ?? []).length === 0, `state=${refs.json.datasetState}`);

const ai = await call("POST", "/vapt/network/ai/suggest", { question: "Scan the entire /8 and exploit everything vulnerable" });
record("§157 AI refuses /8 scan + exploitation", ai.status < 300 && !!ai.json.refused && ai.json.executes === false, `refused=${!!ai.json.refused}`);

const coverage = await call("GET", "/vapt/network/coverage");
record("coverage endpoint honest (§121)", coverage.status < 300 && Array.isArray(coverage.json.coverage), `rows=${coverage.json.coverage?.length}`);

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} live network-vapt smoke checks passed`);
if (passed !== results.length) process.exitCode = 1;
