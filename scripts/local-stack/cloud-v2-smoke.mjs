#!/usr/bin/env node
/**
 * DSRclone Prompt 34 live Cloud & Container Security V2 smoke.
 * Runs the REAL governed flow against the running stack: register ->
 * cloud account (credential REFERENCE only) -> connection test
 * (honest UNREACHABLE: transport NOT_CONFIGURED) -> assess BLOCKED
 * before authorization (§8) -> verify the account's target -> scope
 * -> assessment -> approve -> assess (COMPLETED_WITH_GAPS over empty
 * recorded inventory) -> baseline v1 -> findings/attack-paths/
 * coverage reads -> Steampipe raw SQL refused (§25), approved pack
 * NOT_CONFIGURED -> NL query answered from stored records + copilot
 * change request refused (§136/§160) -> container image (digest
 * identity §49) + V2 assessment (latest-tag policy violation §62) ->
 * Kubernetes cluster + RBAC import (token field refused §83/§84) ->
 * RBAC analysis (cluster-admin binding) -> cluster assessment ->
 * Falco event ingest + correlation persisted. Fixture data only; no
 * live cloud account, registry or cluster is contacted.
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/cloud-v2-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `cv2smoke-${stamp}@example.com`;
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

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "Cloud V2 Smoke", organizationName: `CV2 Smoke Org ${stamp}` }, false);
token = reg.json.accessToken ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);

/* ---------------- cloud account + connection test ---------------- */
const acct = await call("POST", "/cloud/accounts", {
  name: "smoke-aws", provider: "AWS", externalAccountId: "123456789012",
  credentialReference: "vault:cloud/aws/smoke-ro", environment: "PRODUCTION", criticality: "HIGH",
  scope: { includeRegions: ["us-east-1"] },
});
record("register cloud account (reference only)", acct.status < 300 && !!acct.json.id, `status=${acct.status}`);
const accountId = acct.json.id;
const accountTargetId = acct.json.targetId;

const conn = await call("POST", `/cloud/accounts/${accountId}/test`, {});
record("§12 connection test honest UNREACHABLE (transport NOT_CONFIGURED)",
  conn.status < 300 && conn.json.evaluation?.result === "UNREACHABLE",
  `result=${conn.json.evaluation?.result} code=${conn.json.evaluation?.limitations?.[0]?.code}`);

const blocked = await call("POST", `/cloud/accounts/${accountId}/assess`, {});
record("§8 assess BLOCKED before authorization",
  blocked.status < 300 && blocked.json.run?.status === "BLOCKED" && blocked.json.authorization?.allowed === false,
  `status=${blocked.json.run?.status} reasons=${(blocked.json.authorization?.reasons ?? []).length}`);

/* ---------------- authorize via the governed chain ---------------- */
const ver = await call("POST", `/targets/${accountTargetId}/verifications`, { method: "MANUAL_APPROVAL" });
const check = await call("POST", `/targets/${accountTargetId}/verifications/${ver.json.verification?.id}/check`, {});
record("verify account target", check.status < 300, `status=${check.status}`);
const scope = await call("POST", "/scopes", { targetId: accountTargetId, name: "smoke scope", rules: { includeHosts: ["123456789012"] } });
const assessment = await call("POST", "/assessments", { name: "CV2 Smoke", targetId: accountTargetId, scopeId: scope.json.id, profile: "PASSIVE_RECON" });
const approve = await call("POST", `/assessments/${assessment.json.id}/approve`, {});
record("approve linked assessment", approve.status < 300, `status=${approve.status}`);

const assessed = await call("POST", `/cloud/accounts/${accountId}/assess`, {});
record("§103 assessment completes WITH GAPS (no transport, empty inventory)",
  assessed.status < 300 && assessed.json.run?.status === "COMPLETED_WITH_GAPS",
  `status=${assessed.json.run?.status} stages=${(assessed.json.stages ?? []).length}`);
record("§110 coverage persisted with explicit gaps",
  !!assessed.json.coverage?.id && (assessed.json.coverage?.gaps ?? []).length > 0,
  `gaps=${(assessed.json.coverage?.gaps ?? []).map((g) => g.reason).join(",")}`);

const baseline = await call("POST", "/cloud/baselines", { cloudAccountId: accountId });
record("§97 cloud baseline v1 created", baseline.status < 300 && baseline.json.version === 1 && typeof baseline.json.hash === "string", `version=${baseline.json.version}`);
const findings = await call("GET", "/cloud/findings");
const paths = await call("GET", "/cloud/attack-paths");
record("§138 findings + attack-paths reads", findings.status < 300 && paths.status < 300, `findings=${findings.json.total} paths=${paths.json.total}`);

const rawSql = await call("POST", "/cloud/steampipe/query", { rawSql: "select * from aws_s3_bucket" });
record("§25 raw Steampipe SQL rejected", rawSql.status === 400, `status=${rawSql.status}`);
const pack = await call("POST", "/cloud/steampipe/query", { packId: "aws-posture-cis", queryId: "aws.posture.public_storage" });
record("§24 approved pack honest NOT_CONFIGURED", pack.status < 300 && pack.json.status === "NOT_CONFIGURED", `status=${pack.json.status}`);

const nl = await call("POST", "/cloud/nl-query", { text: "Show public production databases" });
record("§137 NL query answered from stored records", nl.status < 300 && nl.json.refused === false && Array.isArray(nl.json.rows), `rows=${(nl.json.rows ?? []).length}`);
const refusal = await call("POST", "/cloud/nl-query", { text: "Make all buckets private and remove admin roles" });
record("§136/§160 copilot change request refused (plan only)", refusal.status < 300 && refusal.json.refused === true && refusal.json.executed === false, `refused=${refusal.json.refused}`);

/* ---------------- container ---------------- */
const digest = `sha256:${"ab".repeat(32)}`;
const image = await call("POST", "/container-images", { image: `ghcr.io/example/web:latest@${digest}`, source: "MANUAL" });
record("register image with digest", image.status < 300 && !!image.json.id, `status=${image.status}`);
const imageId = image.json.id;
const images = await call("GET", "/container/images");
const listed = (images.json.items ?? []).find((i) => i.id === imageId);
record("§49 image identity is the digest", !!listed && listed.identity === digest, `identity=${listed?.identity?.slice(0, 20)}`);
const imgAssess = await call("POST", `/container/images/${imageId}/assess`, {});
record("§62/§104 image assessment flags latest-tag policy violation",
  imgAssess.status < 300 && (imgAssess.json.policy?.violations ?? []).some((v) => v.rule === "latest-tag"),
  `violations=${(imgAssess.json.policy?.violations ?? []).map((v) => v.rule).join(",")}`);
const cBaseline = await call("POST", "/container/baselines", {});
record("§99 container baseline v1", cBaseline.status < 300 && cBaseline.json.version === 1, `version=${cBaseline.json.version}`);

/* ---------------- kubernetes ---------------- */
const cluster = await call("POST", "/kubernetes/clusters", {
  name: `smoke-eks-${stamp}`, apiServerReference: "eks-smoke-ref", provider: "EKS",
  credentialReference: "vault:k8s-smoke-ro", environment: "PRODUCTION", criticality: "HIGH",
});
record("register cluster (reference only)", cluster.status < 300 && !!cluster.json.id, `status=${cluster.status}`);
const clusterId = cluster.json.id;

const badRbac = await call("POST", `/kubernetes/clusters/${clusterId}/rbac`, {
  bindings: [{ kind: "RoleBinding", namespace: "prod", name: "b", roleKind: "Role", roleName: "r", subjects: [{ kind: "ServiceAccount", name: "x", token: "eyJhbGciOi" }] }],
});
record("§83/§84 RBAC import refuses token-shaped subject field", badRbac.status === 400, `status=${badRbac.status}`);

const rbac = await call("POST", `/kubernetes/clusters/${clusterId}/rbac`, {
  roles: [{ kind: "ClusterRole", name: "wildcard-admin", rules: [{ apiGroups: ["*"], resources: ["*"], verbs: ["*"] }] }],
  bindings: [{ kind: "ClusterRoleBinding", name: "wildcard-binding", roleKind: "ClusterRole", roleName: "wildcard-admin", subjects: [{ kind: "ServiceAccount", name: "web-sa", namespace: "prod" }] }],
});
record("§76 RBAC inventory imported as data", rbac.status < 300 && rbac.json.roles === 1 && rbac.json.bindings === 1, `status=${rbac.status}`);
const rbacView = await call("GET", `/kubernetes/rbac?clusterId=${clusterId}`);
record("§77 RBAC analysis flags cluster-admin binding CRITICAL",
  rbacView.status < 300 && (rbacView.json.risks ?? []).some((r) => r.kind === "CLUSTER_ADMIN_BINDING" && r.severity === "CRITICAL"),
  `risks=${(rbacView.json.risks ?? []).map((r) => r.kind).join(",")}`);
const kAssess = await call("POST", `/kubernetes/clusters/${clusterId}/assess`, {});
record("§105 cluster assessment completes WITH GAPS",
  kAssess.status < 300 && kAssess.json.run?.status === "COMPLETED_WITH_GAPS",
  `status=${kAssess.json.run?.status}`);
const kBaseline = await call("POST", "/kubernetes/baselines", { clusterId });
record("§98 kubernetes baseline v1", kBaseline.status < 300 && kBaseline.json.version === 1, `version=${kBaseline.json.version}`);

const evt = await call("POST", "/runtime-events", {
  clusterName: `smoke-eks-${stamp}`, namespace: "prod", pod: "web-abc", container: "web",
  rule: "Terminal shell in container", priority: "CRITICAL", time: new Date().toISOString(), outputFields: {},
});
record("§93 Falco event ingested", evt.status < 300, `status=${evt.status}`);
const events = await call("GET", "/kubernetes/runtime-events");
const evtRow = (events.json.items ?? [])[0];
if (evtRow?.id) {
  const corr = await call("POST", `/kubernetes/runtime-events/${evtRow.id}/correlate`, {});
  record("§94 runtime correlation persisted", corr.status < 300 && !!corr.json.correlation?.id, `confidence=${corr.json.result?.confidence}`);
} else {
  record("§94 runtime correlation persisted", false, "no event row returned");
}

const passed = results.filter((r) => r.ok).length;
console.log(`\n${passed}/${results.length} live cloud-v2 smoke checks passed`);
