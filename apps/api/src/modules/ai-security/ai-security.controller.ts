import { Body, Controller, Get, Inject, Param, Patch, Post, Query } from "@nestjs/common";
import { z } from "zod";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AiCopilotService } from "./ai-copilot.service";
import { AiPlatformService } from "./ai-platform.service";
import { AiConfigService } from "./ai-config.service";
import { AiRouterService } from "./ai-router.service";
import { AiRetrievalService } from "./ai-retrieval.service";
import { AiGatewayService } from "./ai-gateway.service";
import { AiPlannerService } from "./ai-planner.service";
import { AiAgentsService } from "./ai-agents.service";
import { AiV2PlatformService } from "./ai-v2-platform.service";

/**
 * AI Security Copilot API (Prompt 21 §114/§115). The surface accepts
 * analysis requests ONLY: no raw shell, no scanner commands, no raw
 * SQL, no arbitrary scripts, no tool definitions (§115). Execution-
 * shaped chat input is refused inside the service and audited (§7).
 */

const chatSchema = z.object({
  conversationId: z.string().uuid().optional(),
  message: z.string().min(1).max(8000),
  contextType: z.enum(["WORKSPACE", "FINDING", "ASSET", "SCAN", "REPORT", "CVE"]).optional(),
  contextId: z.string().uuid().optional(),
});
const explainSchema = z.object({
  audience: z.enum(["EXECUTIVE", "DEVELOPER", "SECURITY_ANALYST"]).optional(),
  question: z.string().max(2000).optional(),
});
const querySchema = z.object({ question: z.string().min(3).max(1000) });
const feedbackSchema = z.object({
  messageId: z.string().uuid().optional(),
  requestLogId: z.string().uuid().optional(),
  task: z.string().max(60).optional(),
  // Prompt 36 §98/§99: extended ratings + analyst correction.
  rating: z.enum(["HELPFUL", "NOT_HELPFUL", "INCORRECT", "MISSING_EVIDENCE", "UNSAFE", "OUTDATED", "OTHER"]),
  comment: z.string().max(2000).optional(),
  correction: z.string().max(4000).optional(),
});
const proposeSchema = z.object({
  actionType: z.enum(["REQUEST_VALIDATION", "REQUEST_RETEST", "ASSIGN_FINDING", "CREATE_REPORT_DRAFT"]),
  targetType: z.string().min(1).max(60),
  targetId: z.string().min(1).max(200),
  summary: z.string().min(3).max(1000),
});
const knowledgeSchema = z.object({
  title: z.string().min(1).max(200),
  source: z.string().min(1).max(200),
  classification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"]).optional(),
  content: z.string().min(1).max(300000),
});

@Controller("ai")
export class AiSecurityController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly copilot: AiCopilotService,
    private readonly platform: AiPlatformService,
    private readonly config: AiConfigService,
    private readonly router: AiRouterService,
    private readonly retrieval: AiRetrievalService,
    private readonly gateway: AiGatewayService,
    private readonly planner: AiPlannerService,
    private readonly agents: AiAgentsService,
    private readonly v2: AiV2PlatformService,
  ) {}

  // ---- §114 core task routes ----
  @Post("chat")
  async chat(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.chat(user, ws.id, parseOrThrow(chatSchema, body ?? {}));
  }

  @Post("findings/:id/explain")
  async explain(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.explainFinding(user, ws.id, id, parseOrThrow(explainSchema, body ?? {}));
  }

  @Post("findings/:id/remediation")
  async remediation(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.findingTask(user, ws.id, id, "REMEDIATION_GUIDANCE");
  }

  @Post("findings/:id/secure-code")
  async secureCode(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.findingTask(user, ws.id, id, "SECURE_CODE_GUIDANCE");
  }

  @Post("findings/:id/risk-explanation")
  async riskExplanation(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.findingTask(user, ws.id, id, "RISK_EXPLANATION");
  }

  @Post("scans/:id/summary")
  async scanSummary(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.scanSummary(user, ws.id, id);
  }

  @Post("assets/:id/summary")
  async assetSummary(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.assetSummary(user, ws.id, id);
  }

  @Post("query")
  async query(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(querySchema, body ?? {});
    return this.platform.query(user, ws.id, parsed.question);
  }

  @Post("reports/:id/draft")
  async draftReport(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({ section: z.string().max(120).optional() }), body ?? {});
    return this.copilot.draftFromReport(user, ws.id, id, parsed);
  }

  @Post("actions/propose")
  async propose(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.proposeAction(user, ws.id, parseOrThrow(proposeSchema, body ?? {}));
  }

  @Post("feedback")
  async feedback(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.submitFeedback(user, ws.id, parseOrThrow(feedbackSchema, body ?? {}));
  }

  @Get("providers/health")
  async providerHealth(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.providerHealth(ws.id);
  }

  // ---- conversations (§59–§61) ----
  @Get("conversations")
  async conversations(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.listConversations(user, ws.id);
  }

  @Get("conversations/:id")
  async conversation(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.copilot.getConversation(user, ws.id, id);
  }

  // ---- dashboard / usage (§108/§118) ----
  @Get("dashboard")
  async dashboard(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.dashboard(user, ws.id);
  }

  @Get("usage")
  async usage(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.usage(user, ws.id);
  }

  // ---- actions (§83) ----
  @Get("actions")
  async actions(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.listProposals(user, ws.id);
  }

  @Post("actions/:id/decision")
  async decide(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({ decision: z.enum(["APPROVED", "REJECTED", "DISMISSED"]) }), body ?? {});
    return this.platform.decideProposal(user, ws.id, id, parsed.decision);
  }

  // ---- knowledge (§70) ----
  @Get("knowledge")
  async knowledge(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.listKnowledgeDocuments(user, ws.id);
  }

  @Post("knowledge")
  async addKnowledge(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.addKnowledgeDocument(user, ws.id, parseOrThrow(knowledgeSchema, body ?? {}));
  }

  @Get("knowledge/search")
  async searchKnowledge(@CurrentUser() user: RequestUser, @Query("q") q: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.searchKnowledge(user, ws.id, q ?? "");
  }

  // ---- suggested patches (§34) ----
  @Get("patches")
  async patches(@CurrentUser() user: RequestUser, @Query("findingId") findingId?: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.prisma.aiSuggestedPatch.findMany({ where: { workspaceId: ws.id, ...(findingId ? { findingId } : {}) }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  @Patch("patches/:id")
  async reviewPatch(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({ status: z.enum(["REVIEWED", "ACCEPTED", "REJECTED", "SUPERSEDED"]) }), body ?? {});
    const patch = await this.prisma.aiSuggestedPatch.findFirst({ where: { id, workspaceId: ws.id } });
    if (!patch) return { error: "patch not found in this workspace" };
    return this.prisma.aiSuggestedPatch.update({ where: { id }, data: { status: parsed.status, reviewedBy: user.id } });
  }

  // ---- admin: providers / models / policy (§109) ----
  @Get("admin/providers")
  async adminProviders(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.listProviders(ws.id);
  }

  @Post("admin/providers")
  async createProvider(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.createProvider(user, ws.id, body ?? {});
  }

  @Patch("admin/providers/:id")
  async updateProvider(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.updateProvider(user, ws.id, id, body ?? {});
  }

  @Get("admin/models")
  async adminModels(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.listModels(ws.id);
  }

  @Post("admin/models")
  async createModel(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.createModel(user, ws.id, body ?? {});
  }

  @Get("admin/policy")
  async getPolicy(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return { policy: await this.config.getPolicy(ws.id), budget: await this.config.getBudget(ws.id) };
  }

  @Patch("admin/policy")
  async updatePolicy(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.updatePolicy(user, ws.id, body ?? {});
  }

  @Patch("admin/budget")
  async updateBudget(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.updateBudget(user, ws.id, body ?? {});
  }

  @Post("evaluations/run")
  async runEvaluation(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.platform.runEvaluation(user, ws.id);
  }

  // =====================================================================
  // Prompt 36 §141: AI Security Copilot V2 surface. Same rule as V1:
  // analysis + governed proposals only. No route here executes a
  // scan, a shell command, SQL, or any tool outside the gateway
  // catalog (§26/§115).
  // =====================================================================

  @Post("copilot")
  async copilotV2(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      query: z.string().min(1).max(8000),
      taskType: z.string().max(60).optional(),
      conversationId: z.string().uuid().optional(),
    }), body ?? {});
    return this.agents.securityQa(user, ws.id, parsed);
  }

  @Post("analyze/finding/:id")
  async analyzeFinding(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.agents.analyzeFinding(user, ws.id, id);
  }

  @Post("analyze/asset/:id")
  async analyzeAsset(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.agents.analyzeAsset(user, ws.id, id);
  }

  @Post("analyze/incident/:id")
  async analyzeIncident(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.agents.analyzeIncident(user, ws.id, id);
  }

  @Post("analyze/finding/:id/remediation-agent")
  async remediationAgent(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.agents.remediationGuidance(user, ws.id, id);
  }

  // ---- model router (§5/§6) ----
  @Get("router/models")
  async routerModels(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.router.capabilities(user, ws.id);
  }

  @Post("router/route")
  async routerRoute(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      taskType: z.string().min(1).max(60),
      maxClassification: z.enum(["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "SECRET"]).optional(),
    }), body ?? {});
    return this.router.route(user, ws.id, parsed.taskType as never, parsed.maxClassification);
  }

  // ---- permission-aware retrieval (§10) ----
  @Post("retrieval")
  async retrieve(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      sourceTypes: z.array(z.string().max(40)).max(21).optional(),
      maxRecords: z.number().int().min(1).max(100).optional(),
    }), body ?? {});
    return this.retrieval.retrieve(user, ws.id, parsed as never);
  }

  // ---- tool gateway (§27) ----
  @Get("tools")
  async tools(@CurrentUser() user: RequestUser) {
    await resolveWorkspace(this.prisma, user);
    return this.gateway.catalog(user);
  }

  @Post("tools/:name/call")
  async callTool(@CurrentUser() user: RequestUser, @Param("name") name: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      args: z.record(z.string(), z.unknown()).optional(),
      hasApproval: z.boolean().optional(),
      authorizationValid: z.boolean().optional(),
    }), body ?? {});
    // NOTE: hasApproval / authorizationValid flags from the client are
    // never trusted on their own for RESTRICTED actions — the planner
    // workflow passes them internally after a recorded human approval.
    // Direct API callers get the default (false) treatment unless the
    // flags are set AND the gateway's own checks pass; the audit log
    // records every call either way (§133).
    return this.gateway.callTool(user, ws.id, name, parsed.args ?? {}, {
      hasApproval: parsed.hasApproval ?? false,
      authorizationValid: parsed.authorizationValid ?? false,
    });
  }

  // ---- plans + workflows + approvals (§41–§50, §141) ----
  @Post("plans")
  async createPlan(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      taskType: z.enum(["SCAN_PLAN_DRAFT", "VERIFICATION_PLAN", "REMEDIATION_PLAN", "INVESTIGATION_PLAN"]).optional(),
      objective: z.string().max(500).optional(),
      targetIds: z.array(z.string().max(100)).max(50).optional(),
      profile: z.string().max(80).optional(),
      findingId: z.string().uuid().optional(),
      incidentId: z.string().uuid().optional(),
    }), body ?? {});
    return this.planner.createPlan(user, ws.id, parsed);
  }

  @Get("plans")
  async listPlans(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.planner.listPlans(user, ws.id);
  }

  @Get("plans/:id")
  async getPlan(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.planner.getPlan(user, ws.id, id);
  }

  @Get("approvals")
  async listApprovals(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.planner.listApprovals(user, ws.id);
  }

  @Post("workflows/:id/approve")
  async approveWorkflow(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.planner.approveWorkflow(user, ws.id, id);
  }

  @Post("workflows/:id/reject")
  async rejectWorkflow(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.planner.rejectWorkflow(user, ws.id, id);
  }

  @Post("workflows/:id/execute")
  async executeWorkflow(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.planner.executeWorkflow(user, ws.id, id);
  }

  @Post("autonomous/analyze")
  async autonomousAnalyze(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      trigger: z.string().min(1).max(60),
      findingId: z.string().uuid().optional(),
    }), body ?? {});
    return this.planner.analyzeTrigger(user, ws.id, parsed);
  }

  // ---- traces / observability (§128–§131) ----
  @Get("traces")
  async traces(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.listTraces(user, ws.id);
  }

  @Get("observability")
  async observability(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.observability(user, ws.id);
  }

  // ---- memory (§95–§97) ----
  @Get("memory")
  async getMemory(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.getMemory(user, ws.id);
  }

  @Post("memory")
  async setMemory(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({ key: z.string().min(1).max(80), value: z.record(z.string(), z.unknown()) }), body ?? {});
    return this.v2.setMemory(user, ws.id, parsed);
  }

  @Post("memory/delete")
  async deleteMemory(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({ key: z.string().min(1).max(80) }), body ?? {});
    return this.v2.deleteMemory(user, ws.id, parsed.key);
  }

  // ---- report drafts (§144) ----
  @Post("report-drafts")
  async createReportDraft(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({
      reportId: z.string().uuid(), section: z.string().max(120).optional(), title: z.string().max(200).optional(),
    }), body ?? {});
    return this.v2.createReportDraft(user, ws.id, parsed);
  }

  @Get("report-drafts")
  async listReportDrafts(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.listReportDrafts(user, ws.id);
  }

  @Post("report-drafts/:id/review")
  async reviewReportDraft(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const parsed = parseOrThrow(z.object({ status: z.enum(["IN_REVIEW", "APPROVED", "FINALIZED"]) }), body ?? {});
    return this.v2.reviewReportDraft(user, ws.id, id, parsed);
  }

  // ---- evaluations (§100, §141) ----
  @Get("evaluations")
  async listEvaluations(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.listEvaluations(user, ws.id);
  }

  @Post("evaluations/run-v2")
  async runEvaluationV2(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.runEvaluationV2(user, ws.id);
  }

  // ---- daily summaries (§155) ----
  @Get("summaries/daily")
  async dailySummaries(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.v2.dailySummaries(user, ws.id);
  }

  // ---- workspace AI settings (§139) ----
  @Get("settings")
  async getSettings(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    const row = await this.prisma.aiWorkspacePolicy.findFirst({ where: { workspaceId: ws.id } });
    return {
      policy: row ?? null,
      budget: await this.config.getBudget(ws.id),
      routing: await this.config.getRoutingPolicy(ws.id),
      // §140: platform hard safety controls are listed for visibility
      // and are NOT workspace-configurable.
      hardSafetyControls: [
        "AI has no execution surface (no shell/SQL/scanner/cloud/Kubernetes/device access)",
        "AI cannot create or expand authorization, approve its own actions, or grant RBAC",
        "SECRET-classified data never routes to external providers",
        "Raw secrets are redacted before any provider call",
        "Cross-tenant retrieval is impossible by construction",
      ],
    };
  }

  @Patch("settings")
  async updateSettings(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.config.updatePolicy(user, ws.id, body ?? {});
  }
}
