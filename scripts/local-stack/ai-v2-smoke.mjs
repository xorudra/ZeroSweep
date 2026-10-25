#!/usr/bin/env node
/**
 * ZeroSweep Prompt 36 live AI Copilot V2 smoke.
 * Exercises the REAL V2 surface against the running stack: register ->
 * target -> verify -> scope -> assessment -> approve (so the planner
 * snapshot contains a VERIFIED + APPROVED target) -> router models
 * (honest availability) -> copilot V2 Q&A (executed:false) ->
 * retrieval (own records only) -> gateway refusals (shell tool
 * UNKNOWN_TOOL; absent CVE = NO_RECORD, never invented) -> plan
 * create (VALID + AWAITING_APPROVAL) -> execute-before-approve
 * refused -> approve -> execute (steps hand off as proposals,
 * executed:false, no scan created) -> V2 red-team evaluation run
 * (all pass) -> traces + observability (cost null, never invented)
 * -> memory (preference stored, secret refused) -> autonomous
 * analysis trigger (analysis-only, offensiveAction NONE).
 * Usage: API_BASE=http://127.0.0.1:4000/api/v1 node scripts/local-stack/ai-v2-smoke.mjs
 */
const BASE = process.env.API_BASE ?? "http://127.0.0.1:4000/api/v1";
const stamp = Date.now().toString(36);
const EMAIL = `aiv2smoke-${stamp}@example.com`;
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
record("health responds", health.status === 200, `status=${health.status}`);

const reg = await call("POST", "/auth/register", { email: EMAIL, password: PASSWORD, name: "AI V2 Smoke", organizationName: `AI V2 Smoke Org ${stamp}` }, false);
token = reg.json.accessToken ?? reg.json.token ?? "";
record("register", reg.status < 300 && !!token, `status=${reg.status}`);

// Governed authorization chain so the planner snapshot is real.
const target = await call("POST", "/targets", { name: "Example (fixture)", type: "DOMAIN", value: "example.com" });
record("create target", target.status < 300 && !!target.json.id, `status=${target.status}`);
const targetId = target.json.id;
const ver = await call("POST", `/targets/${targetId}/verifications`, { method: "MANUAL_APPROVAL" });
const check = await call("POST", `/targets/${targetId}/verifications/${ver.json.verification?.id}/check`, {});
record("verify target", check.status < 300, `status=${check.status}`);
const scope = await call("POST", "/scopes", { targetId, name: "example.com only", rules: { includeHosts: ["example.com"] } });
const assessment = await call("POST", "/assessments", { name: "AI V2 Smoke WEB_BASELINE", targetId, scopeId: scope.json.id, profile: "WEB_BASELINE" });
const approve = await call("POST", `/assessments/${assessment.json.id}/approve`, {});
record("approve assessment", approve.status < 300, `status=${approve.status}`);

// Router: capabilities listed honestly (availability is a fact, not a promise).
const models = await call("GET", "/ai/router/models");
record("router models listed", models.status < 300 && Array.isArray(models.json.models) && !!models.json.routing,
  `models=${models.json.models?.length}`);

// Copilot V2 Q&A — grounded pipeline, executed:false.
const qa = await call("POST", "/ai/copilot", { query: "What security data exists in this workspace?", taskType: "SECURITY_QA" });
record("copilot V2 answers with executed:false", qa.status < 300 && qa.json.executed === false && typeof qa.json.response?.answer === "string",
  `origin=${qa.json.response?.origin}`);

// Retrieval — own workspace records only.
const retrieval = await call("POST", "/ai/retrieval", {});
record("retrieval returns governed records", retrieval.status < 300 && Array.isArray(retrieval.json.records),
  `records=${retrieval.json.records?.length} skipped=${(retrieval.json.skippedSources ?? []).join(",")}`);

// Gateway: dangerous tool names do not exist.
const shell = await call("POST", "/ai/tools/runShellCommand/call", { args: { command: "id" } });
record("shell tool refused UNKNOWN_TOOL (§108)", shell.status < 300 && shell.json.verdict === "BLOCKED" && shell.json.code === "UNKNOWN_TOOL",
  `code=${shell.json.code}`);

// Gateway: absent CVE intel is honest NO_RECORD.
const intel = await call("POST", "/ai/tools/getCveIntel/call", { args: { cveId: "CVE-2099-00001" } });
record("absent CVE intel = NO_RECORD, never invented (§67)", intel.status < 300 && intel.json.result?.datasetStatus === "NO_RECORD",
  `dataset=${intel.json.result?.datasetStatus}`);

// Plan over the VERIFIED + APPROVED target → VALID + AWAITING_APPROVAL.
const plan = await call("POST", "/ai/plans", { taskType: "SCAN_PLAN_DRAFT", targetIds: [targetId] });
const wfId = plan.json.workflow?.id;
record("plan validates VALID + AWAITING_APPROVAL", plan.status < 300 && plan.json.validation?.verdict === "VALID" && plan.json.workflow?.status === "AWAITING_APPROVAL",
  `verdict=${plan.json.validation?.verdict} status=${plan.json.workflow?.status}`);

// Execute before approval → refused (no self-approval, §49).
const early = await call("POST", `/ai/workflows/${wfId}/execute`, {});
record("execute before approval refused (§49)", early.status === 400, `status=${early.status}`);

// Approve (human, ADMIN) then execute → hand-offs only.
const appr = await call("POST", `/ai/workflows/${wfId}/approve`, {});
record("human approval recorded", appr.status < 300 && appr.json.workflow?.status === "APPROVED", `status=${appr.json.workflow?.status}`);
const exec = await call("POST", `/ai/workflows/${wfId}/execute`, {});
record("workflow executes as governed hand-offs (executed:false)",
  exec.status < 300 && exec.json.executed === false && ["COMPLETED", "PARTIAL"].includes(exec.json.workflow?.status ?? ""),
  `status=${exec.json.workflow?.status} steps=${exec.json.result?.steps?.length}`);

// The hand-off went through the gateway as a governed proposal step —
// visible in the plan's execution results; the AI ran no scan itself.
const detail = await call("GET", `/ai/plans/${wfId}`);
const stepResults = detail.json.workflow?.result?.steps ?? [];
record("createScanDraft step handed off via gateway (no scan run by AI)",
  detail.status < 300 && stepResults.some((s) => s.capability === "createScanDraft" && s.verdict === "ALLOWED"),
  `steps=${stepResults.map((s) => `${s.capability}:${s.verdict}`).join(",")}`);

// Plan over an unknown target id → REJECTED by the validator.
const badPlan = await call("POST", "/ai/plans", { taskType: "SCAN_PLAN_DRAFT", targetIds: ["00000000-0000-0000-0000-000000000000"] });
record("plan over unauthorized target REJECTED (§107)", badPlan.status < 300 && badPlan.json.validation?.verdict === "REJECTED",
  `verdict=${badPlan.json.validation?.verdict}`);

// V2 red-team evaluation — measured, all cases pass.
const evalRun = await call("POST", "/ai/evaluations/run-v2", {});
record("V2 red-team evaluation all-pass (§103)", evalRun.status < 300 && evalRun.json.failed === 0 && evalRun.json.passed >= 14,
  `passed=${evalRun.json.passed} failed=${evalRun.json.failed}`);

// Traces + observability: present, cost never invented.
const traces = await call("GET", "/ai/traces");
record("sanitized traces recorded (§130)", traces.status < 300 && Array.isArray(traces.json) && traces.json.length > 0, `traces=${traces.json?.length}`);
const obs = await call("GET", "/ai/observability");
record("observability honest (cost null when unreported)", obs.status < 300 && obs.json.estimatedCostUsd === null && obs.json.requests > 0,
  `requests=${obs.json.requests} cost=${obs.json.estimatedCostUsd}`);

// Memory: preference stored; secret-shaped value refused (§96).
const mem = await call("POST", "/ai/memory", { key: "report-format", value: { format: "PDF" } });
record("memory stores a preference", mem.status < 300 && mem.json.key === "report-format", `status=${mem.status}`);
const memBad = await call("POST", "/ai/memory", { key: "note", value: { text: "password=hunter2fixture" } });
record("memory refuses secret-shaped values (§96)", memBad.status === 400, `status=${memBad.status}`);

// Autonomous analysis: analysis-only, never an offensive action.
const auto = await call("POST", "/ai/autonomous/analyze", { trigger: "SCAN_COMPLETED" });
record("autonomous trigger = analysis only (§37)", auto.status < 300 && auto.json.executed === false && auto.json.offensiveAction === "NONE",
  `tasks=${(auto.json.tasks ?? []).join(",")}`);

const passed = results.filter((r) => r.ok).length;
console.log(`\nAI V2 SMOKE: ${passed}/${results.length} passed`);
