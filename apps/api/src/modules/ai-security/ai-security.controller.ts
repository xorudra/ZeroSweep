import { Body, Controller, Get, Inject, Param, Patch, Post, Query } from "@nestjs/common";
import { z } from "zod";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AiCopilotService } from "./ai-copilot.service";
import { AiPlatformService } from "./ai-platform.service";
import { AiConfigService } from "./ai-config.service";

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
  rating: z.enum(["HELPFUL", "NOT_HELPFUL", "INCORRECT", "UNSAFE", "OUTDATED"]),
  comment: z.string().max(2000).optional(),
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
}
