import {
  BadRequestException, Body, Controller, Get, Inject, Param, Post, Put, Query, Req,
} from "@nestjs/common";
import { z } from "zod";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { ValidationWorkflowService } from "./workflows/validation-workflow.service";
import { ValidationApprovalsService } from "./approvals/approvals.service";
import { ValidationEvidenceService } from "./evidence/evidence.service";
import { ValidationSessionsService } from "./sessions/sessions.service";
import { ValidationPoliciesService } from "./policies/policies.service";
import { KillSwitchService } from "./safety/kill-switch.service";
import { ValidationCallbackService } from "./callbacks/callback.service";
import { ValidationReportsService } from "./reports/validation-reports.service";

/**
 * Controlled validation API (Prompt 16 §78/§79). Schemas are STRICT:
 * unknown keys are rejected, so raw shell commands, scanner CLI
 * arguments, arbitrary payloads and scripts can never enter through a
 * validation endpoint (§79) — the governed plan builder enforces the
 * same rejection again in the SDK (§90 defense in depth).
 */
const budgetSchema = z.object({
  maxRequests: z.number().int().positive().optional(),
  maxDurationSeconds: z.number().int().positive().optional(),
  maxConcurrency: z.number().int().positive().optional(),
  maxBytes: z.number().int().positive().optional(),
  maxRedirects: z.number().int().min(0).optional(),
  maxEndpoints: z.number().int().positive().optional(),
  maxTargets: z.number().int().positive().optional(),
}).strict();

const createSchema = z.object({
  findingId: z.string().min(1),
  validatorSlug: z.string().min(1).max(128).optional(),
  technique: z.string().min(1).max(128).optional(),
  reason: z.string().max(2000).optional(),
  parameters: z.record(z.union([z.string().max(512), z.number(), z.boolean()])).optional(),
  budget: budgetSchema.optional(),
  idempotencyKey: z.string().min(1).max(128).optional(),
  allowDuplicate: z.boolean().optional(),
  // §65: LAB is an explicit marker set by the requester — never inferred.
  environment: z.enum(["PRODUCTION", "LAB"]).optional(),
}).strict();

const reasonSchema = z.object({ reason: z.string().max(2000).optional() }).strict();

const policySchema = z.object({
  productionPolicy: z.enum(["SAFE_ONLY", "SAFE_AND_LOW_IMPACT_WITH_APPROVAL"]).optional(),
  defaultRiskLevel: z.string().max(32).optional(),
  separationOfDuties: z.boolean().optional(),
  allowIntrusiveInLab: z.boolean().optional(),
  allowedValidators: z.array(z.string().max(128)).max(64).optional(),
  hardLimits: budgetSchema.optional(),
  defaultBudget: budgetSchema.optional(),
  defaultTimeoutSeconds: z.number().int().positive().optional(),
  approvalTtlMinutes: z.number().int().positive().optional(),
  evidenceRetentionDays: z.number().int().positive().optional(),
  callbackEnabled: z.boolean().optional(),
}).strict();

const killSwitchSchema = z.object({
  level: z.string().min(1).max(32),
  scopeRef: z.string().max(128).optional(),
  reason: z.string().max(2000).optional(),
}).strict();

const callbackTokenSchema = z.object({
  requestId: z.string().optional(),
  sessionId: z.string().optional(),
  ttlSeconds: z.number().int().positive().optional(),
}).strict();

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const result = schema.safeParse(body ?? {});
  if (!result.success) {
    throw new BadRequestException(`invalid request: ${result.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`);
  }
  return result.data;
}

@Controller("validations")
export class SecurityValidationController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly workflows: ValidationWorkflowService,
    private readonly approvals: ValidationApprovalsService,
    private readonly evidence: ValidationEvidenceService,
    private readonly sessions: ValidationSessionsService,
    private readonly policies: ValidationPoliciesService,
    private readonly killSwitches: KillSwitchService,
    private readonly callbacks: ValidationCallbackService,
    private readonly reports: ValidationReportsService,
  ) {}

  private async ws(req: { headers: Record<string, unknown> }, user: RequestUser) {
    return resolveWorkspace(this.prisma, user, req.headers["x-workspace-id"] as string | undefined);
  }

  /** §78: POST /api/v1/validations */
  @Post()
  async create(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const input = parse(createSchema, body);
    return this.workflows.createValidation(user, ws.id, input);
  }

  /** §78: GET /api/v1/validations */
  @Get()
  async list(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Query("status") status?: string, @Query("findingId") findingId?: string, @Query("targetId") targetId?: string) {
    const ws = await this.ws(req, user);
    return this.workflows.listValidations(ws.id, { status, findingId, targetId });
  }

  /** §54/§82: dashboard buckets + observability metrics. */
  @Get("dashboard")
  async dashboard(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }) {
    const ws = await this.ws(req, user);
    return this.workflows.dashboard(ws.id, user.organizationId);
  }

  /** §60: report classification summary. */
  @Get("reports/summary")
  async reportSummary(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }) {
    const ws = await this.ws(req, user);
    return this.reports.classificationSummary(ws.id);
  }

  /** §77: workspace validation policy. */
  @Get("policy")
  async getPolicy(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }) {
    const ws = await this.ws(req, user);
    return this.policies.getPolicy(ws.id);
  }

  @Put("policy")
  async updatePolicy(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    return this.policies.updatePolicy(user, ws.id, parse(policySchema, body));
  }

  /** §43: kill switches. */
  @Get("kill-switches")
  async listKillSwitches(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }) {
    const ws = await this.ws(req, user);
    return this.killSwitches.list(user, ws.id);
  }

  @Post("kill-switches")
  async activateKillSwitch(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    return this.killSwitches.activate(user, ws.id, parse(killSwitchSchema, body));
  }

  @Post("kill-switches/:id/clear")
  async clearKillSwitch(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.killSwitches.clear(user, ws.id, id);
  }

  /** §47: issue a controlled callback token (hash stored, token shown once). */
  @Post("callback-tokens")
  async issueCallbackToken(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    return this.callbacks.issueToken(user, ws.id, parse(callbackTokenSchema, body));
  }

  /** §48/§50: public callback ingestion — the token correlates, it
   *  never authorizes; the response exposes no tenant metadata. */
  @Public()
  @Post("callbacks/:token")
  async ingestCallback(@Param("token") token: string, @Req() req: { headers: Record<string, unknown>; ip?: string }, @Body() body: unknown) {
    const kind = (body as { kind?: string } | null)?.kind;
    return this.callbacks.ingest(token, { kind, sourceIp: req.ip });
  }

  /** §78: GET /api/v1/validations/:id */
  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.workflows.getValidation(ws.id, id);
  }

  /** §78: POST /api/v1/validations/:id/approve */
  @Post(":id/approve")
  async approve(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const { reason } = parse(reasonSchema, body);
    return this.approvals.approve(user, ws.id, id, reason);
  }

  /** §78: POST /api/v1/validations/:id/reject */
  @Post(":id/reject")
  async reject(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const { reason } = parse(reasonSchema, body);
    return this.approvals.reject(user, ws.id, id, reason);
  }

  /** §78: POST /api/v1/validations/:id/cancel */
  @Post(":id/cancel")
  async cancel(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.workflows.cancelValidation(user, ws.id, id);
  }

  /** §78: GET /api/v1/validations/:id/evidence */
  @Get(":id/evidence")
  async listEvidence(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.evidence.listForRequest(user, ws.id, id);
  }

  /** §57: sessions for a request. */
  @Get(":id/sessions")
  async listSessions(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    await this.workflows.getValidation(ws.id, id);
    return this.sessions.listForRequest(ws.id, id);
  }

  /** §57: one session in detail. */
  @Get("sessions/:sessionId")
  async getSession(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("sessionId") sessionId: string) {
    const ws = await this.ws(req, user);
    return this.sessions.getSession(ws.id, sessionId);
  }

  /** §61: proof of validation. */
  @Get(":id/proof")
  async proof(@CurrentUser() user: RequestUser, @Req() req: { headers: Record<string, unknown> }, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    return this.reports.proofOfValidation(user, ws.id, id);
  }
}
