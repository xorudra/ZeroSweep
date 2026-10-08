import { BadRequestException, ForbiddenException } from "@nestjs/common";
import { AiCopilotService } from "./ai-copilot.service";
import { AiPlatformService } from "./ai-platform.service";
import { AiConfigService } from "./ai-config.service";
import { AiContextService } from "./ai-context.service";
import { AiRouterService } from "./ai-router.service";
import { AiRetrievalService } from "./ai-retrieval.service";
import { AiGatewayService } from "./ai-gateway.service";
import { AiPlannerService } from "./ai-planner.service";
import { AiAgentsService } from "./ai-agents.service";
import { AiV2PlatformService } from "./ai-v2-platform.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Prompt 36 API tests: model router (§5/§6), permission-aware
 * retrieval (§10–§13), tool gateway (§27–§35), planner + approvals +
 * workflow execution (§41–§50), agents (§51–§57), memory (§95/§96),
 * report drafts + fact check (§90/§144), V2 evaluation (§100–§118),
 * autonomous analysis (§37–§40) and cross-tenant isolation (§105).
 * All in-memory; no provider transport is configured, so copilot
 * narratives are the honest RULE_BASED / NOT_CONFIGURED path.
 */

const WS = "ws-1";
const OTHER = "ws-2";
const admin: RequestUser = { id: "u-admin", email: "rudra@example.com", organizationId: "org-1", role: "ADMIN" };
const admin2: RequestUser = { id: "u-admin2", email: "second@example.com", organizationId: "org-1", role: "ADMIN" };
const analyst: RequestUser = { id: "u-analyst", email: "an@example.com", organizationId: "org-1", role: "ANALYST" };
const viewer: RequestUser = { id: "u-viewer", email: "v@example.com", organizationId: "org-1", role: "VIEWER" };

type Row = Record<string, unknown> & { id: string };
const TABLES = [
  "finding", "findingObservation", "findingEvidence", "asset", "scan", "scanStage", "toolExecution",
  "cveRecord", "cweRecord", "epssRecord", "kevRecord", "reportSnapshot", "securityReport",
  "aiProviderConfig", "aiModel", "aiWorkspacePolicy", "aiUsageBudget", "aiConversation", "aiMessage",
  "aiRequestLog", "aiCitation", "aiSuggestedPatch", "aiActionProposal", "aiFeedback",
  "knowledgeDocument", "aiEmbedding", "aiEvaluationRun", "auditLog",
  // Prompt 36 tables + governed domain tables the V2 services read.
  "aiSecurityWorkflow", "aiActionApproval", "aiSecurityTrace", "aiCopilotMemory", "aiReportDraft",
  "target", "assessment", "securityIncident", "incidentTimelineEntry", "incidentLink",
  "softwareComponent", "remediationCase", "aiDailySecuritySummary",
] as const;

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (v === undefined) continue;
    if (k === "OR") { if (!((v as Record<string, unknown>[]).some((w) => matches(row, w)))) return false; continue; }
    const rv = row[k];
    if (v !== null && typeof v === "object" && !(v instanceof Date)) {
      const cond = v as Record<string, unknown>;
      if ("in" in cond && !(cond.in as unknown[]).includes(rv)) return false;
      if ("gte" in cond && !((rv as Date) >= (cond.gte as Date))) return false;
      if ("lte" in cond && !((rv as Date) <= (cond.lte as Date))) return false;
      if ("contains" in cond && !(typeof rv === "string" && rv.toLowerCase().includes(String(cond.contains).toLowerCase()))) return false;
      continue;
    }
    if (rv !== v) return false;
  }
  return true;
}

function makeFake() {
  const tables: Record<string, Row[]> = Object.fromEntries(TABLES.map((t) => [t, []]));
  let seq = 0;
  const model = (name: string) => ({
    async findMany(args: { where?: Record<string, unknown>; orderBy?: unknown; take?: number } = {}) {
      let out = tables[name]!.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy : args.orderBy ? [args.orderBy] : [];
      for (const ob of [...orderBy].reverse()) {
        const [field, dir] = Object.entries(ob as Record<string, string>)[0]!;
        out = [...out].sort((a, b) => {
          const av = a[field] as never, bv = b[field] as never;
          const cmp = av === bv ? 0 : av === null || av === undefined ? 1 : bv === null || bv === undefined ? -1 : av < bv ? -1 : 1;
          return dir === "desc" ? -cmp : cmp;
        });
      }
      if (args.take) out = out.slice(0, args.take);
      return out;
    },
    async findFirst(args: { where?: Record<string, unknown>; orderBy?: unknown } = {}) {
      const rows = await this.findMany({ where: args.where, orderBy: args.orderBy, take: 1 });
      return rows[0] ?? null;
    },
    async create(args: { data: Row }) {
      const row: Row = { ...args.data } as Row;
      if (!row.id) row.id = `${name}-${++seq}`;
      row.createdAt ??= new Date();
      row.updatedAt ??= new Date();
      tables[name]!.push(row);
      return row;
    },
    async update(args: { where: { id: string }; data: Row }) {
      const row = tables[name]!.find((r) => r.id === args.where.id);
      if (!row) throw new Error("not found");
      Object.assign(row, args.data);
      return row;
    },
    async delete(args: { where: { id: string } }) {
      const i = tables[name]!.findIndex((r) => r.id === args.where.id);
      if (i >= 0) tables[name]!.splice(i, 1);
      return {};
    },
    async count(args: { where?: Record<string, unknown> } = {}) {
      return tables[name]!.filter((r) => matches(r, args.where)).length;
    },
  });
  const prisma: Record<string, unknown> = {};
  for (const t of TABLES) prisma[t] = model(t);
  return { prisma: prisma as never, tables };
}

function seedCore(tables: Record<string, Row[]>) {
  tables.finding!.push({
    id: "f-1", workspaceId: WS, scanId: "scan-1", assetId: "a-1",
    title: "SQL injection in search parameter", description: "q concatenated into SQL.",
    severity: "HIGH", status: "OPEN", lifecycleStatus: "NEW", verificationStatus: "UNVERIFIED",
    confidence: 0.8, cvssScore: 8.6, cve: null, cwe: "CWE-89", sourceDomain: "WEB",
    fixedVersion: null, filePath: "src/search.ts", remediation: "Use parameterized queries.",
    riskScore: 82, riskBand: "HIGH", fingerprint: "fp-1",
    riskExplanation: { factors: ["base:8.6"], adjustments: [], missingInformation: [] },
    epssScore: null, epssPercentile: null, kevListed: false, environment: "PRODUCTION",
    createdAt: new Date(), updatedAt: new Date(),
  });
  tables.finding!.push({ id: "f-foreign", workspaceId: OTHER, title: "Tenant B critical", severity: "CRITICAL", riskScore: 99, kevListed: true, cve: "CVE-2021-44228", sourceDomain: "WEB", fingerprint: "fp-x", createdAt: new Date(), updatedAt: new Date() });
  tables.asset!.push({ id: "a-1", workspaceId: WS, host: "example.com", type: "WEB_APPLICATION", criticality: "HIGH", scopeStatus: "IN_SCOPE" });
  tables.target!.push({ id: "t-1", workspaceId: WS, name: "example.com", type: "WEB", value: "example.com", verified: true, status: "VERIFIED" });
  tables.target!.push({ id: "t-2", workspaceId: WS, name: "unverified.example.com", type: "WEB", value: "unverified.example.com", verified: false, status: "DRAFT" });
  tables.assessment!.push({ id: "as-1", workspaceId: WS, targetId: "t-1", status: "APPROVED", profile: "WEB_BASELINE" });
  tables.securityIncident!.push({ id: "inc-1", workspaceId: WS, organizationId: "org-1", title: "Suspicious login burst", severity: "HIGH", status: "OPEN", detectedAt: new Date(), createdAt: new Date() });
  tables.incidentTimelineEntry!.push({ id: "tle-1", incidentId: "inc-1", workspaceId: WS, entryType: "DETECTED", summary: "Alert fired from governed detection rule", createdAt: new Date() });
  tables.remediationCase!.push({ id: "rc-1", workspaceId: WS, organizationId: "org-1", findingId: "f-1", status: "IN_PROGRESS", verificationState: "NOT_REQUESTED", dueAt: null });
}

function services() {
  const { prisma, tables } = makeFake();
  seedCore(tables);
  const audit = new AuditService(prisma);
  const config = new AiConfigService(prisma, audit);
  const contexts = new AiContextService(prisma);
  const copilot = new AiCopilotService(prisma, audit, config, contexts);
  const platform = new AiPlatformService(prisma, audit, config);
  const router = new AiRouterService(prisma, config);
  const retrieval = new AiRetrievalService(prisma, audit);
  const gateway = new AiGatewayService(prisma, audit, contexts);
  const planner = new AiPlannerService(prisma, audit, config, gateway, copilot);
  const agents = new AiAgentsService(prisma, audit, gateway, copilot, contexts, router);
  const v2 = new AiV2PlatformService(prisma, audit, planner, copilot);
  return { prisma, tables, audit, config, copilot, platform, router, retrieval, gateway, planner, agents, v2 };
}

describe("model router (§5/§6)", () => {
  it("no models → NOT_CONFIGURED, honestly", async () => {
    const s = services();
    const d = await s.router.route(admin, WS, "SECURITY_QA");
    expect(d.status).toBe("NOT_CONFIGURED");
  });
  it("capabilities returns the { routing, models } shape (§134)", async () => {
    const s = services();
    const caps = await s.router.capabilities(admin, WS);
    expect(Array.isArray(caps.models)).toBe(true);
    expect(caps.routing.approvalPolicy).toBeDefined();
  });
  it("MOCK model with capabilities routes; residency filters external models", async () => {
    const s = services();
    s.tables.aiProviderConfig!.push({ id: "p-1", workspaceId: WS, name: "mock", providerType: "MOCK", isExternal: false, enabled: true, region: null, approvedClassifications: ["PUBLIC", "INTERNAL"], sourceCodeAllowance: "REDACTED", healthStatus: "HEALTHY" });
    s.tables.aiModel!.push({ id: "m-1", workspaceId: WS, providerId: "p-1", modelName: "mock-1", capabilities: ["GENERATE"], contextLimit: 16384, enabled: true, healthStatus: "HEALTHY", structuredOutputSupport: true, toolCallingSupport: true, embeddingSupport: true, costClass: "FREE", latencyClass: "FAST" });
    const d = await s.router.route(admin, WS, "SCAN_PLAN_DRAFT");
    expect(d.status).toBe("ROUTED");
    expect(d.model?.modelName).toBe("mock-1");
  });
});

describe("permission-aware retrieval (§10–§13, §105)", () => {
  it("returns own-workspace records only; foreign findings never appear", async () => {
    const s = services();
    const out = await s.retrieval.retrieve(admin, WS, {});
    const ids = out.records.map((r) => r.sourceId);
    expect(ids).toContain("f-1");
    expect(ids).not.toContain("f-foreign");
  });
  it("VIEWER holds no copilot permission at all → refused at the door (§116)", async () => {
    const s = services();
    await expect(s.retrieval.retrieve(viewer, WS, {})).rejects.toThrow(/lacks permission/);
  });
  it("ANALYST lacks AI_DRAFT_REPORT → REPORT source skipped and disclosed (§21)", async () => {
    const s = services();
    const out = await s.retrieval.retrieve(analyst, WS, {});
    expect(out.skippedSources).toContain("REPORT");
    expect(out.records.some((r) => r.sourceId === "f-1")).toBe(true); // findings ARE permitted for staff
  });
});

describe("tool gateway (§27–§35, §108–§113)", () => {
  it("governed read tool works and writes a sanitized trace", async () => {
    const s = services();
    const out = await s.gateway.callTool(admin, WS, "getFinding", { findingId: "f-1" });
    expect(out.verdict).toBe("ALLOWED");
    expect(out.executed).toBe(false);
    expect(s.tables.aiSecurityTrace!.length).toBeGreaterThan(0);
    const traceJson = JSON.stringify(s.tables.aiSecurityTrace![0]);
    expect(traceJson).not.toContain("SQL injection in search"); // args/values never logged (§132)
  });
  it("shell/SQL/kubectl/frida/exploit names are refused as UNKNOWN_TOOL", async () => {
    const s = services();
    for (const name of ["runShellCommand", "executeSql", "kubectlExec", "runFridaScript", "exploitFinding"]) {
      const out = await s.gateway.callTool(admin, WS, name, {});
      expect(out.verdict).toBe("BLOCKED");
      expect(out.code).toBe("UNKNOWN_TOOL");
    }
  });
  it("restricted action without authorization+approval is blocked (§35)", async () => {
    const s = services();
    const out = await s.gateway.callTool(admin, WS, "scheduleApprovedScan", { planId: "p-1" });
    expect(out.verdict).toBe("BLOCKED");
    expect(["AUTHORIZATION_REQUIRED", "APPROVAL_REQUIRED"]).toContain(out.code);
  });
  it("absent CVE intel is honest NO_RECORD, never invented (§67)", async () => {
    const s = services();
    const out = await s.gateway.callTool(admin, WS, "getCveIntel", { cveId: "CVE-2099-00001" });
    expect(out.verdict).toBe("ALLOWED");
    expect((out.result as { datasetStatus: string }).datasetStatus).toBe("NO_RECORD");
  });
  it("cross-tenant finding id behaves as nonexistent (§105)", async () => {
    const s = services();
    await expect(s.gateway.callTool(admin, WS, "getFinding", { findingId: "f-foreign" })).rejects.toThrow(/not found/);
  });
});

describe("planner + approvals + workflows (§41–§50)", () => {
  it("scan plan over a VERIFIED+APPROVED target → AWAITING_APPROVAL with a pending approval", async () => {
    const s = services();
    const out = await s.planner.createPlan(admin, WS, { taskType: "SCAN_PLAN_DRAFT", targetIds: ["t-1"] });
    expect(out.workflow.status).toBe("AWAITING_APPROVAL");
    expect(out.validation.verdict).toBe("VALID");
    expect(out.approval?.decision).toBe("PENDING");
    expect(out.executed).toBe(false);
  });
  it("plan over an UNVERIFIED target → REJECTED by the deterministic validator", async () => {
    const s = services();
    const out = await s.planner.createPlan(admin, WS, { taskType: "SCAN_PLAN_DRAFT", targetIds: ["t-2"] });
    expect(out.workflow.status).toBe("REJECTED");
    expect(out.validation.verdict).toBe("REJECTED");
  });
  it("out-of-scope third-party target → REJECTED (§107)", async () => {
    const s = services();
    const out = await s.planner.createPlan(admin, WS, { taskType: "SCAN_PLAN_DRAFT", targetIds: ["thirdparty.example.net"] });
    expect(out.validation.verdict).toBe("REJECTED");
  });
  it("approve (different admin) → execute → steps handed off, executed:false preserved", async () => {
    const s = services();
    const created = await s.planner.createPlan(admin, WS, { taskType: "SCAN_PLAN_DRAFT", targetIds: ["t-1"] });
    const wfId = created.workflow.id as string;
    const approved = await s.planner.approveWorkflow(admin2, WS, wfId);
    expect(approved.workflow.status).toBe("APPROVED");
    const executed = await s.planner.executeWorkflow(admin, WS, wfId);
    expect(["COMPLETED", "PARTIAL"]).toContain(executed.workflow.status);
    expect(executed.executed).toBe(false);
    // The createScanDraft step produced a governed proposal, not a scan.
    expect(s.tables.aiActionProposal!.some((p) => p.actionType === "CREATE_SCAN_DRAFT")).toBe(true);
    expect(s.tables.scan ?? []).toHaveLength(0);
  });
  it("executing an unapproved workflow is refused — no self-approval (§49)", async () => {
    const s = services();
    const created = await s.planner.createPlan(admin, WS, { taskType: "SCAN_PLAN_DRAFT", targetIds: ["t-1"] });
    await expect(s.planner.executeWorkflow(admin, WS, created.workflow.id as string)).rejects.toThrow(BadRequestException);
  });
  it("separation of duties: requester cannot approve own HIGH-risk approval (§143)", async () => {
    const s = services();
    s.tables.aiSecurityWorkflow!.push({ id: "wf-high", workspaceId: WS, requestedBy: admin.id, taskType: "SCAN_PLAN_DRAFT", objective: "high risk", mode: "PLANNING", status: "AWAITING_APPROVAL", plan: {}, validation: {}, createdAt: new Date(), updatedAt: new Date() });
    s.tables.aiActionApproval!.push({ id: "ap-high", workspaceId: WS, workflowId: "wf-high", requestedBy: admin.id, reason: "high risk action", riskClass: "CRITICAL", scope: {}, decision: "PENDING", expiresAt: new Date(Date.now() + 3600000), createdAt: new Date() });
    await expect(s.planner.approveWorkflow(admin, WS, "wf-high")).rejects.toThrow(ForbiddenException);
    const ok = await s.planner.approveWorkflow(admin2, WS, "wf-high");
    expect(ok.workflow.status).toBe("APPROVED");
  });
  it("expired approval cannot be reused (§50)", async () => {
    const s = services();
    s.tables.aiSecurityWorkflow!.push({ id: "wf-old", workspaceId: WS, requestedBy: admin.id, taskType: "SCAN_PLAN_DRAFT", objective: "old", mode: "PLANNING", status: "AWAITING_APPROVAL", plan: {}, validation: {}, createdAt: new Date(), updatedAt: new Date() });
    s.tables.aiActionApproval!.push({ id: "ap-old", workspaceId: WS, workflowId: "wf-old", requestedBy: admin.id, reason: "old", riskClass: "LOW", scope: {}, decision: "PENDING", expiresAt: new Date(Date.now() - 1000), createdAt: new Date() });
    await expect(s.planner.approveWorkflow(admin2, WS, "wf-old")).rejects.toThrow(ForbiddenException);
  });
});

describe("agents (§51–§57)", () => {
  it("analyzeFinding returns a grounded envelope with executed:false", async () => {
    const s = services();
    const out = await s.agents.analyzeFinding(admin, WS, "f-1");
    expect(out.executed).toBe(false);
    expect(out.answer.length).toBeGreaterThan(0);
    expect(out.structuredOk).toBe(true);
    expect((out.agentRun as { status: string }).status).toBeDefined();
  });
  it("analyzeFinding on a foreign finding 404s (§105)", async () => {
    const s = services();
    await expect(s.agents.analyzeFinding(admin, WS, "f-foreign")).rejects.toThrow(/not found/);
  });
  it("analyzeIncident builds an OBSERVED timeline + UNVERIFIED hypotheses (§84/§85)", async () => {
    const s = services();
    const out = await s.agents.analyzeIncident(admin, WS, "inc-1");
    expect(out.executed).toBe(false);
    const structured = out.structuredOutput as { events: { kind: string }[]; hypotheses: { verificationStatus: string }[] };
    expect(structured.events[0]?.kind).toBe("OBSERVED");
    expect(structured.hypotheses[0]?.verificationStatus).toBe("UNVERIFIED");
    expect(out.answer).not.toMatch(/attributed to|threat actor/i);
  });
});

describe("memory / feedback / evaluations / autonomous (§95–§118, §37)", () => {
  it("memory stores preferences but refuses secret-shaped values (§96)", async () => {
    const s = services();
    const row = await s.v2.setMemory(analyst, WS, { key: "report-format", value: { format: "PDF" } });
    expect(row.key).toBe("report-format");
    await expect(s.v2.setMemory(analyst, WS, { key: "note", value: { text: "password=hunter2fixture" } })).rejects.toThrow(BadRequestException);
    await expect(s.v2.setMemory(analyst, WS, { key: "api-key", value: { v: "x" } })).rejects.toThrow(BadRequestException);
  });
  it("feedback accepts MISSING_EVIDENCE + correction (§98/§99)", async () => {
    const s = services();
    const row = await s.platform.submitFeedback(analyst, WS, { rating: "MISSING_EVIDENCE", correction: "The asset was decommissioned in March." });
    expect(row.correction).toContain("decommissioned");
    expect(s.tables.auditLog!.some((a) => a.action === "AI_FEEDBACK_RECEIVED")).toBe(true);
  });
  it("V2 evaluation run measures the red-team suite + live-snapshot cases (§103)", async () => {
    const s = services();
    const run = await s.v2.runEvaluationV2(admin, WS);
    expect(run.suite).toBe("V2_REDTEAM");
    expect(run.failed).toBe(0);
    expect(run.passed).toBeGreaterThanOrEqual(14);
  });
  it("autonomous trigger produces analysis-only work (§37–§40)", async () => {
    const s = services();
    const out = await s.planner.analyzeTrigger(admin, WS, { trigger: "CRITICAL_FINDING_CREATED", findingId: "f-1" });
    expect(out.executed).toBe(false);
    expect(out.offensiveAction).toBe("NONE");
    expect(out.tasks).toContain("REMEDIATION_DRAFT");
    await expect(s.planner.analyzeTrigger(admin, WS, { trigger: "LAUNCH_EXPLOIT" })).rejects.toThrow(BadRequestException);
  });
  it("observability aggregates without inventing cost (§128)", async () => {
    const s = services();
    await s.agents.analyzeFinding(admin, WS, "f-1");
    const obs = await s.v2.observability(admin, WS);
    expect(obs.requests).toBeGreaterThan(0);
    expect(obs.estimatedCostUsd).toBeNull();
  });
});
