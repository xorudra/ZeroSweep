import { describe, expect, it } from "vitest";
import { buildFindingContext, aiCacheKey, trimContext } from "./context";
import { redactClassifiedFields, redactForAi } from "./redaction";
import { scanForInjection } from "./injection";
import { evaluateAiTaskPolicy, isExecutionShapedRequest } from "./policy";
import { buildAiPrompt, AI_SYSTEM_POLICY } from "./prompts";
import { groundAnswer, computeAiConfidence, validateStructuredOutput } from "./grounding";
import { MockAiProvider, UnconfiguredAiProvider, AiProviderError, citationsFromAnswer, ruleBasedAnswer } from "./provider";
import { parseSecurityQuery, validateQueryPlan, executeSecurityQuery, type SecurityQueryRow } from "./query";
import { embedText, ingestKnowledgeDocument, searchVectors, type VectorRecord } from "./knowledge";
import { sanitizeAiMarkdown, evaluateAiBudget } from "./output";
import {
  GOLDEN_FIXTURES, INJECTION_EVIDENCE_TEXT, SECRET_BEARING_EVIDENCE, SECRET_FIXTURE_STRINGS,
} from "./evaluation";
import type { AiProviderDataPolicy, AiWorkspaceAccessPolicy } from "./types";

const WS_POLICY: AiWorkspaceAccessPolicy = { sourceCodeAccess: "REDACTED", rawEvidenceAccess: "SANITIZED_ONLY", enabledTasks: [] };
const EXTERNAL_PROVIDER: AiProviderDataPolicy = {
  providerName: "ext-1", providerType: "OPENAI_COMPATIBLE", isExternal: true,
  approvedClassifications: ["PUBLIC", "INTERNAL", "CONFIDENTIAL"], sourceCodeAllowance: "REDACTED", enabled: true,
};
const LOCAL_PROVIDER: AiProviderDataPolicy = { ...EXTERNAL_PROVIDER, providerName: "local-1", providerType: "LOCAL", isExternal: false, approvedClassifications: ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"] };

describe("redaction (§14/§15/§93)", () => {
  it("strips every synthetic secret from provider-bound text", () => {
    const r = redactForAi(SECRET_BEARING_EVIDENCE);
    for (const s of SECRET_FIXTURE_STRINGS) expect(r.text).not.toContain(s);
    expect(r.text).not.toContain("MIIFixtureKeyMaterial");
    expect(r.count).toBeGreaterThan(0);
  });
  it("removes SECRET fields entirely rather than masking them", () => {
    const r = redactClassifiedFields([
      { key: "title", value: "ok", classification: "INTERNAL" },
      { key: "psk", value: "some-wifi-passphrase", classification: "SECRET" },
    ]);
    expect(r.fields.map((f) => f.key)).toEqual(["title"]);
    expect(r.removed).toEqual(["psk"]);
  });
});

describe("task policy (§6/§16/§17/§107)", () => {
  const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "FINDING_EXPLANATION");
  it("denies SECRET data to external providers absolutely", () => {
    const d = evaluateAiTaskPolicy({ task: "FINDING_EXPLANATION", maxClassification: "SECRET", includesSourceCode: false, includesRawEvidence: false, provider: EXTERNAL_PROVIDER, workspace: WS_POLICY });
    expect(d.decision).toBe("DENY");
  });
  it("allows SECRET data to a local provider that approved it", () => {
    const d = evaluateAiTaskPolicy({ task: "FINDING_EXPLANATION", maxClassification: "SECRET", includesSourceCode: false, includesRawEvidence: false, provider: LOCAL_PROVIDER, workspace: WS_POLICY });
    expect(d.decision).not.toBe("DENY");
  });
  it("denies classifications above provider approval", () => {
    const d = evaluateAiTaskPolicy({ task: "FINDING_EXPLANATION", maxClassification: "RESTRICTED", includesSourceCode: false, includesRawEvidence: false, provider: EXTERNAL_PROVIDER, workspace: WS_POLICY });
    expect(d.decision).toBe("DENY");
  });
  it("requires review for secure-code guidance and report drafting", () => {
    const d = evaluateAiTaskPolicy({ task: "SECURE_CODE_GUIDANCE", maxClassification: ctx.maxClassification, includesSourceCode: false, includesRawEvidence: false, provider: EXTERNAL_PROVIDER, workspace: WS_POLICY });
    expect(d.decision).toBe("REQUIRE_REVIEW");
  });
  it("honestly reports NOT_CONFIGURED when no provider exists", () => {
    const d = evaluateAiTaskPolicy({ task: "FINDING_EXPLANATION", maxClassification: "INTERNAL", includesSourceCode: false, includesRawEvidence: false, provider: null, workspace: WS_POLICY });
    expect(d.providerConfigured).toBe(false);
  });
  it("denies tasks disabled by workspace policy", () => {
    const d = evaluateAiTaskPolicy({ task: "COPILOT_CHAT", maxClassification: "INTERNAL", includesSourceCode: false, includesRawEvidence: false, provider: EXTERNAL_PROVIDER, workspace: { ...WS_POLICY, enabledTasks: ["FINDING_EXPLANATION"] } });
    expect(d.decision).toBe("DENY");
  });
});

describe("context builder (§9/§10/§33/§101)", () => {
  it("builds least-context: only the one finding's records", () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "FINDING_EXPLANATION");
    expect(ctx.records.every((r) => ["f-sqli", "a-web", "ev-sqli"].includes(r.sourceId))).toBe(true);
    expect(ctx.contextHash).toMatch(/^[a-f0-9]{64}$/);
  });
  it("risk explanation uses ONLY the stored RiskEngine V3 signals (§101)", () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "RISK_EXPLANATION");
    const rec = ctx.records.find((r) => r.fields.riskSignals);
    expect(rec?.fields.riskSignals).toContain("internet_facing");
    expect(rec?.fields.riskEngineVersion).toBe("risk-v3.0");
  });
  it("includes intel records for CVE findings", () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[3]!.finding, "FINDING_EXPLANATION");
    const types = ctx.records.map((r) => r.sourceType);
    expect(types).toContain("CVE"); expect(types).toContain("EPSS"); expect(types).toContain("KEV");
  });
  it("includes a code snippet only for code-oriented tasks and caps it (§33)", () => {
    const f = { ...GOLDEN_FIXTURES[1]!.finding, codeSnippet: "x".repeat(5000) };
    const withCode = buildFindingContext(f, "SECURE_CODE_GUIDANCE");
    const without = buildFindingContext(f, "SCAN_SUMMARY");
    expect(withCode.includesSourceCode).toBe(true);
    expect(withCode.records.find((r) => r.fields.codeSnippet)?.fields.codeSnippet!.length).toBe(2000);
    expect(without.includesSourceCode).toBe(false);
  });
  it("trims lowest-priority (untrusted) context first (§106)", () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "FINDING_EXPLANATION");
    const trimmed = trimContext(ctx.records, 40);
    expect(trimmed.some((r) => r.trust === "TRUSTED")).toBe(true);
  });
  it("cache key is tenant-bound (§75)", () => {
    const a = aiCacheKey({ workspaceId: "ws-a", task: "FINDING_EXPLANATION", contextHash: "h", modelName: "m", policyVersion: "1", dataVersion: "1" });
    const b = aiCacheKey({ workspaceId: "ws-b", task: "FINDING_EXPLANATION", contextHash: "h", modelName: "m", policyVersion: "1", dataVersion: "1" });
    expect(a).not.toBe(b);
  });
});

describe("prompt injection defenses (§18–§20/§92)", () => {
  it("detects instruction-like evidence patterns", () => {
    const scan = scanForInjection(INJECTION_EVIDENCE_TEXT);
    expect(scan.detections.length).toBeGreaterThanOrEqual(2);
    expect(scan.trustScore).toBeLessThan(1);
  });
  it("does not flag ordinary hashes/digests as encoded instructions", () => {
    const scan = scanForInjection("fingerprint sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 match");
    expect(scan.detections).toEqual([]);
  });
  it("keeps injected text inside the UNTRUSTED section and system policy intact", async () => {
    const f = { ...GOLDEN_FIXTURES[0]!.finding, evidence: [{ id: "ev-inj", sourceTool: "nuclei", summary: INJECTION_EVIDENCE_TEXT, fingerprint: "sha256:x" }] };
    const ctx = buildFindingContext(f, "FINDING_EXPLANATION");
    const prompt = buildAiPrompt({ task: "FINDING_EXPLANATION", context: ctx });
    expect(prompt.system).toBe(AI_SYSTEM_POLICY);
    expect(prompt.sections.untrusted).toContain("Ignore previous instructions");
    expect(prompt.sections.trusted).not.toContain("Ignore previous instructions");
    const provider = new MockAiProvider();
    const out = await provider.generate({ task: "FINDING_EXPLANATION", prompt, modelName: "mock-1" });
    expect(out.text).not.toContain("API keys");
    expect(out.text).toContain("FINDING_EXPLANATION");
  });
});

describe("grounding, hallucination, confidence (§21/§25/§89–§91)", () => {
  it("golden fixtures produce grounded, cited explanations (§87/§90)", async () => {
    for (const fx of GOLDEN_FIXTURES) {
      const ctx = buildFindingContext(fx.finding, "FINDING_EXPLANATION");
      const prompt = buildAiPrompt({ task: "FINDING_EXPLANATION", question: fx.question, context: ctx });
      const out = await new MockAiProvider().generate({ task: "FINDING_EXPLANATION", prompt, modelName: "mock-1" });
      const citations = citationsFromAnswer(out.text, ctx.records);
      const g = groundAnswer({ answer: out.text, proposedCitations: citations, context: ctx });
      expect(g.grounded, fx.id).toBe(true);
      expect(g.citations.length, fx.id).toBeGreaterThan(0);
    }
  });
  it("flags answers referencing identifiers absent from context (§89)", () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[2]!.finding, "FINDING_EXPLANATION");
    const g = groundAnswer({ answer: "This relates to CVE-2099-00001 which is critical.", proposedCitations: [], context: ctx });
    expect(g.unsupportedReferences).toContain("CVE-2099-00001");
    expect(g.grounded).toBe(false);
  });
  it("mock refuses to fabricate about a nonexistent CVE (§89)", async () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[2]!.finding, "FINDING_EXPLANATION");
    const prompt = buildAiPrompt({ task: "FINDING_EXPLANATION", question: "Tell me about CVE-2099-00001", context: ctx });
    const out = await new MockAiProvider().generate({ task: "FINDING_EXPLANATION", prompt, modelName: "mock-1" });
    expect(out.text).toContain("INSUFFICIENT_EVIDENCE");
  });
  it("drops citations that point outside the context", () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "FINDING_EXPLANATION");
    const g = groundAnswer({
      answer: "grounded [f-sqli]",
      proposedCitations: [
        { claim: "real", sourceType: "FINDING", sourceId: "f-sqli", confidence: 0.9 },
        { claim: "fake", sourceType: "FINDING", sourceId: "f-other-tenant", confidence: 0.9 },
      ],
      context: ctx,
    });
    expect(g.citations.map((c) => c.sourceId)).toEqual(["f-sqli"]);
  });
  it("confidence degrades with missing fields and no citations (§26/§91)", () => {
    const low = computeAiConfidence({ citationCoverage: 0, sourceQuality: 0.3, injectionTrust: 1, missingFieldCount: 5 });
    expect(low.level).toBe("LOW");
    const high = computeAiConfidence({ citationCoverage: 1, sourceQuality: 1, scannerConfidence: 0.95, verificationStatus: "CONFIRMED", injectionTrust: 1, missingFieldCount: 0 });
    expect(high.level).toBe("HIGH");
  });
  it("validates structured output shape (§78)", () => {
    expect(validateStructuredOutput({ answer: "x" }, ["answer"]).ok).toBe(true);
    expect(validateStructuredOutput({ answer: "x", evil: 1 }, ["answer"]).ok).toBe(false);
  });
});

describe("natural-language search (§41–§45/§95)", () => {
  const rows: SecurityQueryRow[] = [
    { id: "1", title: "crit prod kev", severity: "CRITICAL", verificationStatus: "CONFIRMED", kevListed: true, sourceDomain: "WEB", environment: "PRODUCTION", riskScore: 95, lifecycleStatus: "NEW" },
    { id: "2", title: "mobile overdue", severity: "HIGH", verificationStatus: "UNVERIFIED", kevListed: false, sourceDomain: "MOBILE", environment: "PRODUCTION", riskScore: 60, lifecycleStatus: "IN_PROGRESS", dueAt: new Date(Date.now() - 86400000) },
    { id: "3", title: "low web", severity: "LOW", verificationStatus: "UNVERIFIED", kevListed: false, sourceDomain: "WEB", environment: "STAGING", riskScore: 10, lifecycleStatus: "NEW" },
  ];
  it("parses the spec's example intents into a typed DSL plan", () => {
    const r = parseSecurityQuery("Show critical verified vulnerabilities on production assets");
    expect("plan" in r && r.plan.severityIn).toEqual(["CRITICAL"]);
    expect("plan" in r && r.plan.verificationStatus).toBe("CONFIRMED");
    const kev = parseSecurityQuery("Which internet-facing assets have KEV findings?");
    expect("plan" in kev && kev.plan.kevOnly).toBe(true);
    const mob = parseSecurityQuery("Show overdue mobile findings");
    expect("plan" in mob && mob.plan.domainIn).toEqual(["MOBILE"]);
    expect("plan" in mob && mob.plan.overdueOnly).toBe(true);
  });
  it("executes plans over authorized rows only", () => {
    const p = parseSecurityQuery("Show critical verified vulnerabilities on production assets");
    if (!("plan" in p)) throw new Error("parse failed");
    expect(executeSecurityQuery(rows, p.plan).map((r) => r.id)).toEqual(["1"]);
    const mob = parseSecurityQuery("Show overdue mobile findings");
    if (!("plan" in mob)) throw new Error("parse failed");
    expect(executeSecurityQuery(rows, mob.plan).map((r) => r.id)).toEqual(["2"]);
  });
  it("rejects SQL-shaped input — never converts it to a query (§95)", () => {
    const r = parseSecurityQuery("show findings'; DROP TABLE findings; --");
    expect("rejected" in r).toBe(true);
    const r2 = parseSecurityQuery("findings UNION SELECT password FROM users");
    expect("rejected" in r2).toBe(true);
  });
  it("validator bounds result size and fields (§44)", () => {
    const p = parseSecurityQuery("critical findings top 500");
    if (!("plan" in p)) throw new Error("parse failed");
    expect(p.plan.limit).toBe(200); // parser clamps to the DSL hard cap
    expect(validateQueryPlan(p.plan, 100).length).toBeGreaterThan(0); // workspace cap is stricter
    expect(validateQueryPlan({ ...p.plan, limit: 10 }, 200)).toEqual([]);
  });
});

describe("knowledge base + vectors (§66–§73/§96/§97)", () => {
  it("ingests hostile documents as data with injection flags, rejects oversized/binary", () => {
    const ok = ingestKnowledgeDocument(`Remediation guide. ${INJECTION_EVIDENCE_TEXT}`);
    expect(ok.accepted).toBe(true);
    expect(ok.injectionFlags).toBeGreaterThan(0);
    expect(ok.contentHash).toMatch(/^[a-f0-9]{64}$/);
    expect(ingestKnowledgeDocument("x".repeat(300_000)).accepted).toBe(false);
    expect(ingestKnowledgeDocument("a\u0000b").accepted).toBe(false);
  });
  it("tenant isolation: identical documents in two tenants never cross (§96)", () => {
    const text = "rotate the krbtgt account password twice with a strong passphrase";
    const records: VectorRecord[] = [
      { workspaceId: "ws-a", sourceType: "KNOWLEDGE_DOCUMENT", sourceId: "doc-a", classification: "INTERNAL", vector: embedText(text) },
      { workspaceId: "ws-b", sourceType: "KNOWLEDGE_DOCUMENT", sourceId: "doc-b", classification: "INTERNAL", vector: embedText(text) },
    ];
    const hits = searchVectors(records, { workspaceId: "ws-a", text: "krbtgt password rotation" });
    expect(hits.length).toBeGreaterThan(0);
    expect(hits.every((h) => h.record.workspaceId === "ws-a")).toBe(true);
  });
  it("classification ceiling is applied before ranking (§68)", () => {
    const records: VectorRecord[] = [
      { workspaceId: "ws-a", sourceType: "KNOWLEDGE_DOCUMENT", sourceId: "doc-secret", classification: "SECRET", vector: embedText("secret rotation guide") },
    ];
    expect(searchVectors(records, { workspaceId: "ws-a", text: "secret rotation guide", maxClassification: "INTERNAL" })).toEqual([]);
  });
});

describe("output safety + budgets (§79/§98/§104/§105)", () => {
  it("sanitizes script tags, event handlers and unsafe links from model output", () => {
    const dirty = `hi <script>alert(1)</script> <img src=x onerror=alert(2)> [click](javascript:alert(3))`;
    const clean = sanitizeAiMarkdown(dirty);
    expect(clean).not.toContain("<script");
    expect(clean).not.toContain("onerror");
    expect(clean).not.toContain("javascript:");
  });
  it("budget gate blocks overspend and rate excess before provider calls", () => {
    const limits = { dailyTokenLimit: 1000, monthlyTokenLimit: 10000, perTaskTokenLimit: 500, maxRequestsPerUserPerDay: 5, maxRequestsPerTaskPerDay: 50 };
    expect(evaluateAiBudget({ tokensToday: 900, tokensThisMonth: 900, requestsTodayByUser: 0, requestsTodayByTask: 0 }, limits, 200).allowed).toBe(false);
    expect(evaluateAiBudget({ tokensToday: 0, tokensThisMonth: 0, requestsTodayByUser: 5, requestsTodayByTask: 0 }, limits, 100).allowed).toBe(false);
    expect(evaluateAiBudget({ tokensToday: 0, tokensThisMonth: 0, requestsTodayByUser: 0, requestsTodayByTask: 0 }, limits, 100).allowed).toBe(true);
  });
});

describe("provider boundary (§3/§7/§99/§103)", () => {
  it("unconfigured provider reports NOT_CONFIGURED and rule-based fallback still answers", async () => {
    const p = new UnconfiguredAiProvider();
    await expect(p.generate()).rejects.toBeInstanceOf(AiProviderError);
    expect((await p.healthCheck()).status).toBe("NOT_CONFIGURED");
    const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "FINDING_EXPLANATION");
    const rb = ruleBasedAnswer("FINDING_EXPLANATION", ctx, []);
    expect(rb.origin).toBe("RULE_BASED");
    expect(rb.answer).toContain("f-sqli");
  });
  it("provider failure surfaces as PROVIDER_ERROR, not a crash (§103)", async () => {
    const ctx = buildFindingContext(GOLDEN_FIXTURES[0]!.finding, "FINDING_EXPLANATION");
    const prompt = buildAiPrompt({ task: "FINDING_EXPLANATION", context: ctx });
    await expect(new MockAiProvider("ERROR").generate({ task: "FINDING_EXPLANATION", prompt, modelName: "m" }))
      .rejects.toMatchObject({ code: "PROVIDER_ERROR" });
  });
  it("flags execution-shaped requests for refusal (§7/§120)", () => {
    expect(isExecutionShapedRequest("run a scan on this target now")).toBe(true);
    expect(isExecutionShapedRequest("please execute shell command ls")).toBe(true);
    expect(isExecutionShapedRequest("explain this finding")).toBe(false);
  });
});
