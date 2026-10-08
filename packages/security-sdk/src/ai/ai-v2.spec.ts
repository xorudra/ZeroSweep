import { describe, expect, it } from "vitest";
import {
  AI_AGENTS, AI_RED_TEAM_CASES, AI_TOOL_CATALOG,
  assessEvidenceFreshness, assessPatchConfidence, authorizationSnapshotHash,
  buildInvestigationTimeline, canTransitionWorkflow, classifyScanProfile,
  detectToolLoop, evaluateAiApproval, evaluateAiToolCall, factCheckReportDraft,
  filterRetrievalCandidates, getAiAgent, getAiTool, planAutomaticAnalysis,
  routeAiModel, runAiRedTeamSuite, runBoundedAgent, summarizeAiObservability,
  toolCallSignature, validateAiPlan, validateAiStructuredOutput, validateCveMentions,
  type AiAuthorizationSnapshot, type AiModelCapability, type AiSecurityPlan,
} from "../index";

/**
 * Prompt 36 SDK tests: model router + residency (§3–§6), permission-
 * aware retrieval + staleness (§10–§18), tool gateway (§27–§35),
 * planner + deterministic validator (§41–§50), agents + loop limits
 * (§51–§60), structured output + CVE/remediation/report validation
 * (§65–§70/§81/§90), autonomous analysis (§37–§40) and the red-team
 * evaluation suite (§100–§118).
 */

const MODEL = (over: Partial<AiModelCapability> = {}): AiModelCapability => ({
  modelId: "m-1", providerName: "mock", providerType: "MOCK", modelName: "mock-1",
  contextWindow: 16384, structuredOutputSupport: true, toolCallingSupport: true,
  embeddingSupport: true, generateSupport: true, availability: "AVAILABLE",
  costClass: "FREE", latencyClass: "FAST", isExternal: false, region: null,
  approvedClassifications: ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], enabled: true,
  ...over,
});

describe("model router (§3–§6)", () => {
  it("routes a structured task to a capable model", () => {
    const d = routeAiModel({ taskType: "SCAN_PLAN_DRAFT", maxClassification: "INTERNAL", models: [MODEL()], policy: { allowedModelIds: [], allowExternalProviders: true } });
    expect(d.status).toBe("ROUTED");
    expect(d.model?.modelId).toBe("m-1");
  });
  it("never downgrades: structured task + no structured model → NOT_CONFIGURED", () => {
    const d = routeAiModel({ taskType: "SCAN_PLAN_DRAFT", maxClassification: "INTERNAL", models: [MODEL({ structuredOutputSupport: false })], policy: { allowedModelIds: [], allowExternalProviders: true } });
    expect(d.status).toBe("NOT_CONFIGURED");
    expect(d.rejected[0]?.reason).toContain("structured-output");
  });
  it("data residency: external provider in the wrong region is rejected (§6)", () => {
    const d = routeAiModel({
      taskType: "SECURITY_QA", maxClassification: "INTERNAL",
      models: [MODEL({ isExternal: true, region: "us", providerType: "OPENAI_COMPATIBLE" })],
      policy: { allowedModelIds: [], allowExternalProviders: true, dataResidencyRegion: "eu" },
    });
    expect(d.status).toBe("NOT_CONFIGURED");
    expect(d.rejected[0]?.reason).toContain("residency");
  });
  it("SECRET never routes externally (§14)", () => {
    const d = routeAiModel({
      taskType: "SECURITY_QA", maxClassification: "SECRET",
      models: [MODEL({ isExternal: true, approvedClassifications: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"] })],
      policy: { allowedModelIds: [], allowExternalProviders: true },
    });
    expect(d.status).toBe("NOT_CONFIGURED");
  });
  it("cost ceiling from tenant policy is enforced (§121)", () => {
    const d = routeAiModel({ taskType: "SECURITY_QA", maxClassification: "INTERNAL", models: [MODEL({ costClass: "HIGH" })], policy: { allowedModelIds: [], allowExternalProviders: true, maxCostClass: "LOW" } });
    expect(d.status).toBe("NOT_CONFIGURED");
  });
});

describe("permission-aware retrieval (§10–§18)", () => {
  const req = {
    workspaceId: "ws-1", userId: "u-1", userPermissions: ["USE_AI_COPILOT"],
    sourcePermissions: { FINDING: "AI_EXPLAIN_FINDING" } as const, classificationCeiling: "INTERNAL" as const, maxRecords: 10,
  };
  it("drops cross-tenant candidates, never re-homes them (§12)", () => {
    const out = filterRetrievalCandidates(req, [
      { sourceType: "ASSET", sourceId: "a-1", workspaceId: "ws-2", classification: "INTERNAL", fields: {} },
      { sourceType: "ASSET", sourceId: "a-2", workspaceId: "ws-1", classification: "INTERNAL", fields: {} },
    ]);
    expect(out.records.map((r) => r.sourceId)).toEqual(["a-2"]);
    expect(out.dropped[0]?.reason).toContain("cross-tenant");
  });
  it("skips sources the user cannot read and discloses the skip (§10)", () => {
    const out = filterRetrievalCandidates(req, [
      { sourceType: "FINDING", sourceId: "f-1", workspaceId: "ws-1", classification: "INTERNAL", fields: {} },
    ]);
    expect(out.skippedSources).toContain("FINDING");
    expect(out.records).toHaveLength(0);
  });
  it("enforces classification ceiling and resource ACL (§10/§13)", () => {
    const out = filterRetrievalCandidates(req, [
      { sourceType: "ASSET", sourceId: "a-secret", workspaceId: "ws-1", classification: "SECRET", fields: {} },
      { sourceType: "ASSET", sourceId: "a-acl", workspaceId: "ws-1", classification: "INTERNAL", aclPrincipals: ["someone-else"], fields: {} },
      { sourceType: "ASSET", sourceId: "a-ok", workspaceId: "ws-1", classification: "INTERNAL", aclPrincipals: ["u-1"], fields: {} },
    ]);
    expect(out.records.map((r) => r.sourceId)).toEqual(["a-ok"]);
    expect(out.dropped).toHaveLength(2);
  });
  it("labels stale evidence (§18)", () => {
    const now = new Date("2026-10-08T00:00:00Z");
    expect(assessEvidenceFreshness("2026-10-01T00:00:00Z", now).state).toBe("STALE");
    expect(assessEvidenceFreshness("2026-10-07T23:00:00Z", now).state).toBe("CURRENT");
    expect(assessEvidenceFreshness(undefined, now).state).toBe("UNKNOWN");
  });
});

describe("tool gateway (§27–§35)", () => {
  const ctx = { userPermissions: ["USE_AI_COPILOT", "AI_EXPLAIN_FINDING"], hasApproval: false, authorizationValid: false, callsThisHour: 0 };
  it("catalog contains no execution surface (§26)", () => {
    for (const t of AI_TOOL_CATALOG) {
      expect(t.name).not.toMatch(/shell|sql|kubectl|exploit|frida/i);
    }
    expect(getAiTool("runShell")).toBeUndefined();
  });
  it("read tool allowed with permission; blocked without", () => {
    expect(evaluateAiToolCall("getFinding", ctx).allowed).toBe(true);
    const denied = evaluateAiToolCall("getFinding", { ...ctx, userPermissions: [] });
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) expect(denied.code).toBe("PERMISSION");
  });
  it("restricted action requires authorization snapshot then approval (§35)", () => {
    const noAuth = evaluateAiToolCall("scheduleApprovedScan", { ...ctx, userPermissions: ["RUN_AI_APPROVED_ACTION"] });
    expect(noAuth.allowed).toBe(false);
    if (!noAuth.allowed) expect(noAuth.code).toBe("AUTHORIZATION_REQUIRED");
    const noApproval = evaluateAiToolCall("scheduleApprovedScan", { ...ctx, userPermissions: ["RUN_AI_APPROVED_ACTION"], authorizationValid: true });
    expect(noApproval.allowed).toBe(false);
    if (!noApproval.allowed) expect(noApproval.code).toBe("APPROVAL_REQUIRED");
    const ok = evaluateAiToolCall("scheduleApprovedScan", { ...ctx, userPermissions: ["RUN_AI_APPROVED_ACTION"], authorizationValid: true, hasApproval: true });
    expect(ok.allowed).toBe(true);
  });
  it("rate limits are enforced per tool (§28)", () => {
    const toolDef = getAiTool("getAsset")!;
    const v = evaluateAiToolCall("getAsset", { ...ctx, callsThisHour: toolDef.rateLimitPerHour });
    expect(v.allowed).toBe(false);
    if (!v.allowed) expect(v.code).toBe("RATE_LIMIT");
  });
  it("loop detection catches repeated equivalent calls (§60)", () => {
    const sig = toolCallSignature("getFinding", { findingId: "f-1" });
    expect(detectToolLoop([sig, sig]).looping).toBe(false);
    expect(detectToolLoop([sig, sig, sig]).looping).toBe(true);
  });
});

const SNAPSHOT: AiAuthorizationSnapshot = {
  snapshotId: "snap-1", workspaceId: "ws-1", scopeHash: "scopehash",
  targets: [{ targetId: "t-1", verified: true, assessmentApproved: true }, { targetId: "t-2", verified: false, assessmentApproved: false }],
  capturedAt: "2026-10-08T00:00:00Z",
};
const PLAN = (over: Partial<AiSecurityPlan> = {}): AiSecurityPlan => ({
  objective: "Assess the authorized application",
  taskType: "SCAN_PLAN_DRAFT", workspaceId: "ws-1",
  authorizationSnapshotHash: authorizationSnapshotHash(SNAPSHOT),
  steps: [{
    id: "s-1", objective: "Baseline web scan", capability: "draftScanPlan", targetReferences: ["t-1"],
    dependencies: [], riskClass: "MEDIUM", requiredPermission: "CREATE_AI_PLAN", approvalRequired: true,
    expectedEvidence: ["scan findings"], scanProfile: "WEB_BASELINE",
  }],
  ...over,
});
const VCTX = {
  userPermissions: ["CREATE_AI_PLAN"], snapshot: SNAPSHOT, availableTools: AI_TOOL_CATALOG.map((t) => t.name),
  budgetRemainingTokens: 100000, estimatedPlanTokens: 1000, riskCeilingWithoutApproval: "MEDIUM" as const, hasApproval: true,
};

describe("planner + validator (§41–§50, §74–§78)", () => {
  it("safe default profile is an approved baseline (§77)", () => {
    expect(classifyScanProfile("WEB_BASELINE")).toBe("APPROVED");
    expect(classifyScanProfile("MOBILE_FULL_CONTROLLED")).toBe("HIGH_IMPACT");
    expect(classifyScanProfile("ANYTHING_GOES")).toBe("UNKNOWN");
  });
  it("a governed plan validates", () => {
    const v = validateAiPlan(PLAN(), VCTX);
    expect(v.verdict).toBe("VALID");
    expect(v.snapshotHashVerified).toBe(true);
  });
  it("snapshot hash mismatch is rejected — snapshot is immutable (§46)", () => {
    const v = validateAiPlan(PLAN({ authorizationSnapshotHash: "tampered" }), VCTX);
    expect(v.verdict).toBe("REJECTED");
    expect(v.snapshotHashVerified).toBe(false);
  });
  it("unverified / unapproved targets are rejected (§44)", () => {
    const v = validateAiPlan(PLAN({ steps: [{ ...PLAN().steps[0]!, targetReferences: ["t-2"] }] }), VCTX);
    expect(v.verdict).toBe("REJECTED");
    expect(v.findings.some((f) => f.reason.includes("not VERIFIED"))).toBe(true);
  });
  it("out-of-scope target is rejected (§107)", () => {
    const v = validateAiPlan(PLAN({ steps: [{ ...PLAN().steps[0]!, targetReferences: ["thirdparty.example.net"] }] }), VCTX);
    expect(v.verdict).toBe("REJECTED");
  });
  it("high-impact profile without approval is rejected (§78)", () => {
    const v = validateAiPlan(
      PLAN({ steps: [{ ...PLAN().steps[0]!, scanProfile: "MOBILE_FULL_CONTROLLED" }] }),
      { ...VCTX, hasApproval: false },
    );
    expect(v.verdict).toBe("REJECTED");
    expect(v.findings.some((f) => f.reason.includes("high-impact"))).toBe(true);
  });
  it("unknown capability and missing snapshot fail closed (§27/§150)", () => {
    const v1 = validateAiPlan(PLAN({ steps: [{ ...PLAN().steps[0]!, capability: "runShellCommand" }] }), VCTX);
    expect(v1.verdict).toBe("REJECTED");
    const v2 = validateAiPlan(PLAN(), { ...VCTX, snapshot: null });
    expect(v2.verdict).toBe("REJECTED");
  });
  it("workflow transitions are a closed state machine (§47)", () => {
    expect(canTransitionWorkflow("DRAFT", "VALIDATING")).toBe(true);
    expect(canTransitionWorkflow("DRAFT", "RUNNING")).toBe(false);
    expect(canTransitionWorkflow("COMPLETED", "RUNNING")).toBe(false);
    expect(canTransitionWorkflow("AWAITING_APPROVAL", "APPROVED")).toBe(true);
  });
  it("AI can never approve; expired approvals cannot be reused; SoD holds (§49/§50/§143)", () => {
    const base = { requestedBy: "u-1", decision: "APPROVED" as const, expiresAt: "2999-01-01T00:00:00Z", now: new Date(), separationOfDuties: true, riskClass: "HIGH" as const };
    expect(evaluateAiApproval({ ...base, approverId: "AI", approverIsAi: true }).accepted).toBe(false);
    expect(evaluateAiApproval({ ...base, approverId: "u-2", approverIsAi: false, expiresAt: "2000-01-01T00:00:00Z" }).accepted).toBe(false);
    expect(evaluateAiApproval({ ...base, approverId: "u-1", approverIsAi: false }).accepted).toBe(false);
    expect(evaluateAiApproval({ ...base, approverId: "u-2", approverIsAi: false }).accepted).toBe(true);
  });
});

describe("agents + orchestrator (§51–§60)", () => {
  it("all seven spec agents exist with bounded limits", () => {
    expect(AI_AGENTS.map((a) => a.name)).toEqual(expect.arrayContaining([
      "SecurityAnalysisAgent", "VulnerabilityAnalysisAgent", "RemediationAgent", "SocInvestigationAgent",
      "CloudSecurityAnalysisAgent", "ApplicationSecurityAgent", "SecurityReportAgent",
    ]));
    for (const a of AI_AGENTS) {
      expect(a.maxSteps).toBeGreaterThan(0);
      expect(a.maxToolCalls).toBeGreaterThan(0);
      expect(a.allowedTools.every((t) => getAiTool(t))).toBe(true);
    }
  });
  it("orchestrator runs allowlisted tools and blocks others", async () => {
    const agent = getAiAgent("VulnerabilityAnalysisAgent")!;
    const out = await runBoundedAgent({
      agent,
      intents: [
        { tool: "getFinding", args: { findingId: "f-1" } },
        { tool: "scheduleApprovedScan", args: { planId: "p-1" } },
      ],
      gateContext: { userPermissions: ["AI_EXPLAIN_FINDING", "USE_AI_COPILOT"], hasApproval: false, authorizationValid: false, callsThisHour: 0 },
      execute: async (tool) => ({ summary: `${tool} ok`, tokens: 10 }),
    });
    expect(out.executed).toBe(false);
    expect(out.steps[0]?.verdict).toBe("ALLOWED");
    expect(out.steps[1]?.verdict).toBe("BLOCKED");
    expect(out.status).toBe("PARTIAL");
  });
  it("orchestrator terminates loops safely (§60)", async () => {
    const agent = getAiAgent("SecurityAnalysisAgent")!;
    const out = await runBoundedAgent({
      agent,
      intents: Array.from({ length: 6 }, () => ({ tool: "getFinding", args: { findingId: "f-1" } })),
      gateContext: { userPermissions: ["AI_EXPLAIN_FINDING"], hasApproval: false, authorizationValid: false, callsThisHour: 0 },
      execute: async () => ({ summary: "ok", tokens: 1 }),
    });
    expect(out.status).toBe("TERMINATED_LOOP");
  });
  it("orchestrator enforces max tool calls (§59)", async () => {
    const agent = { ...getAiAgent("SecurityAnalysisAgent")!, maxToolCalls: 2, maxSteps: 10 };
    const out = await runBoundedAgent({
      agent,
      intents: [
        { tool: "getAsset", args: { assetId: "a-1" } },
        { tool: "getAsset", args: { assetId: "a-2" } },
        { tool: "getAsset", args: { assetId: "a-3" } },
      ],
      gateContext: { userPermissions: ["USE_AI_COPILOT"], hasApproval: false, authorizationValid: false, callsThisHour: 0 },
      execute: async () => ({ summary: "ok", tokens: 1 }),
    });
    expect(out.status).toBe("TERMINATED_LIMIT");
    expect(out.toolCalls).toBe(2);
  });
});

describe("structured output + validations (§65–§70, §81, §85, §90)", () => {
  it("schema validation rejects malformed output (§66)", () => {
    expect(validateAiStructuredOutput("FINDING_SUMMARY", { findingId: "f-1", summary: "s", claims: [] }).ok).toBe(true);
    expect(validateAiStructuredOutput("FINDING_SUMMARY", { findingId: "f-1" }).ok).toBe(false);
    expect(validateAiStructuredOutput("RISK_EXPLANATION", { findingId: "f", riskScore: 1, riskBand: "LOW", factors: [], aiRiskScore: 99 }).ok).toBe(false);
    expect(validateAiStructuredOutput("NOPE", {}).ok).toBe(false);
  });
  it("CVE mentions validate against intel (§68)", () => {
    const v = validateCveMentions("This asset is affected by CVE-2021-44228 and CVE-2099-00001.", ["CVE-2021-44228"]);
    expect(v.validated).toEqual(["CVE-2021-44228"]);
    expect(v.unvalidated).toEqual(["CVE-2099-00001"]);
  });
  it("patch confidence requires trusted intel for VERIFIED_SOURCE (§69/§81)", () => {
    expect(assessPatchConfidence({ claimedFixedVersion: "2.17.0", intelFixedVersions: ["2.17.0"], hasFindingEvidence: true }).confidence).toBe("VERIFIED_SOURCE");
    expect(assessPatchConfidence({ claimedFixedVersion: "9.9.9", intelFixedVersions: ["2.17.0"], hasFindingEvidence: true }).confidence).toBe("GENERAL_GUIDANCE");
    expect(assessPatchConfidence({ claimedFixedVersion: null, intelFixedVersions: [], hasFindingEvidence: false }).confidence).toBe("GENERAL_GUIDANCE");
  });
  it("report fact check catches invented ids, wrong counts and fear language (§90/§92)", () => {
    const bad = factCheckReportDraft({
      draftText: "Finding 123e4567-e89b-12d3-a456-426614174000 caused total devastation, guaranteed breach.",
      canonicalFindingIds: [], canonicalCounts: { total: 3, bySeverity: { HIGH: 1 } }, claimedCounts: { total: 9 },
    });
    expect(bad.ok).toBe(false);
    expect(bad.mismatches.length).toBeGreaterThanOrEqual(3);
    const good = factCheckReportDraft({ draftText: "Three findings remain open.", canonicalFindingIds: [], canonicalCounts: { total: 3, bySeverity: {} }, claimedCounts: { total: 3 } });
    expect(good.ok).toBe(true);
  });
  it("investigation hypotheses are structurally UNVERIFIED (§85)", () => {
    const tl = buildInvestigationTimeline({ events: [{ at: "t", summary: "alert fired", sourceId: "al-1" }], hypotheses: ["possible lateral movement"] });
    expect(tl.events[0]?.kind).toBe("OBSERVED");
    expect(tl.hypotheses[0]?.verificationStatus).toBe("UNVERIFIED");
  });
});

describe("autonomous analysis (§37–§40, §155/§156)", () => {
  it("triggers map to analysis tasks only — never offensive work", () => {
    const item = planAutomaticAnalysis("CRITICAL_FINDING_CREATED");
    expect(item?.executed).toBe(false);
    expect(item?.offensiveAction).toBe("NONE");
    expect(item?.tasks).toContain("REMEDIATION_DRAFT");
    expect(planAutomaticAnalysis("LAUNCH_EXPLOIT")).toBeNull();
    expect(planAutomaticAnalysis("SCAN_COMPLETED")?.tasks).not.toContain("REMEDIATION_DRAFT");
  });
});

describe("red-team evaluation suite (§100–§118)", () => {
  it("all SDK-resident red-team cases pass against the real pipeline", () => {
    const results = runAiRedTeamSuite();
    expect(results.length).toBe(AI_RED_TEAM_CASES.length);
    const failures = results.filter((r) => !r.passed);
    expect(failures).toEqual([]);
  });
  it("observability summary never invents cost (§128)", () => {
    const s = summarizeAiObservability([
      { status: "COMPLETED", task: "SECURITY_QA", latencyMs: 100, promptTokens: 10, completionTokens: 5 },
      { status: "POLICY_BLOCKED", task: "SECURITY_QA", latencyMs: 50, policyDecision: "DENY", injectionFlags: 2 },
    ]);
    expect(s.requests).toBe(2);
    expect(s.policyBlocks).toBe(1);
    expect(s.injectionDetections).toBe(2);
    expect(s.estimatedCostUsd).toBeNull();
  });
});
