import {
  BadRequestException, Body, Controller, Get, Header, Param, Patch, Post, Query, Req,
} from "@nestjs/common";
import { z } from "zod";
import type { VmLifecycleStatus } from "@dsrclone/security-sdk";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { VulnerabilityService } from "./vulnerability.service";
import { IntelligenceService } from "./intelligence.service";
import { RetestService } from "./retest.service";
import { ScannerImportsService } from "./imports.service";
import { requireVmPermission } from "./permissions";
import { AuditService } from "../audit/audit.service";
import { Inject } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";

/**
 * Vulnerability management API (Prompt 11 §80). Findings remain the
 * evidence-backed detections; these endpoints manage lifecycle, owners,
 * intelligence and imports. All routes are JWT-guarded, workspace-scoped
 * and permission-checked (§78); mutations audit (§92).
 */
const transitionSchema = z.object({
  lifecycleStatus: z.enum(["NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED", "RETEST_PENDING", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"]),
  reason: z.string().max(2000).optional(),
  reviewerId: z.string().optional(),
  riskAcceptance: z.object({ approverId: z.string(), expiresAt: z.string().datetime() }).optional(),
});
const assignSchema = z.object({ assignedToId: z.string().nullable().optional(), assignedToTeam: z.string().nullable().optional() });
const commentSchema = z.object({ body: z.string().min(1).max(20000) });
const tagsSchema = z.object({ tags: z.array(z.string().max(64)).max(64) });
const bulkSchema = z.object({
  ids: z.array(z.string()).min(1).max(200),
  action: z.enum(["assign", "tag", "triage", "accept-risk", "false-positive", "request-retest"]),
  assignedToId: z.string().nullable().optional(), assignedToTeam: z.string().nullable().optional(),
  tags: z.array(z.string().max(64)).max(64).optional(),
  reason: z.string().max(2000).optional(), riskAcceptanceExpiresAt: z.string().datetime().optional(),
});
const importSchema = z.object({ scanner: z.enum(["nessus-professional", "greenbone-openvas"]), payload: z.string().min(1).max(12_000_000) });
const commitSchema = z.object({ payload: z.string().min(1).max(12_000_000), scanId: z.string().min(1) });
const slaPolicySchema = z.object({
  name: z.string().min(1).max(120),
  byPriority: z.record(z.number().positive().max(24 * 365)).optional(),
  bySeverity: z.record(z.number().positive().max(24 * 365)).optional(),
});

@Controller("vulnerabilities")
export class VulnerabilitiesController {
  constructor(
    private readonly vulnerabilities: VulnerabilityService,
    private readonly intelligence: IntelligenceService,
    private readonly retests: RetestService,
    private readonly imports: ScannerImportsService,
    private readonly audit: AuditService,
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
  ) {}

  private async ws(req: { headers: Record<string, string | string[] | undefined> }, user: RequestUser) {
    return resolveWorkspace(this.prisma, user, req.headers["x-workspace-id"] as string | undefined);
  }

  @Get("dashboard")
  async dashboard(@Req() req: never, @CurrentUser() user: RequestUser, @Query("days") days?: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.vulnerabilities.dashboard(ws.id, days ? Number(days) : 30);
  }

  @Get("remediation")
  async remediation(@Req() req: never, @CurrentUser() user: RequestUser) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.vulnerabilities.remediationDashboard(ws.id);
  }

  @Get("export")
  @Header("Content-Type", "text/csv")
  async export(@Req() req: never, @CurrentUser() user: RequestUser, @Query("format") format?: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    if (format === "json") return this.vulnerabilities.exportJson(ws.id);
    return this.vulnerabilities.exportCsv(ws.id);
  }

  @Get()
  async list(
    @Req() req: never, @CurrentUser() user: RequestUser,
    @Query("priority") priority?: string, @Query("severity") severity?: string,
    @Query("lifecycleStatus") lifecycleStatus?: string, @Query("owner") owner?: string,
    @Query("host") host?: string, @Query("scanner") scanner?: string,
    @Query("cve") cve?: string, @Query("cwe") cwe?: string,
    @Query("kev") kev?: string, @Query("epssMin") epssMin?: string,
    @Query("sla") sla?: string, @Query("tag") tag?: string, @Query("exposure") exposure?: string,
    @Query("search") search?: string, @Query("sort") sort?: string,
    @Query("page") page?: string, @Query("pageSize") pageSize?: string,
  ) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.vulnerabilities.list(ws.id, {
      priority, severity, lifecycleStatus, assignedToId: owner, host, scanner, cve, cwe,
      ...(kev !== undefined ? { kev: kev === "true" } : {}),
      ...(epssMin !== undefined ? { epssMin: Number(epssMin) } : {}),
      ...(sla ? { sla: sla as never } : {}),
      tag, exposure, search,
      ...(sort ? { sort: sort as never } : {}),
      ...(page ? { page: Number(page) } : {}), ...(pageSize ? { pageSize: Number(pageSize) } : {}),
    });
  }

  @Post("bulk")
  async bulk(@Req() req: never, @CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = bulkSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.bulk(user, ws.id, {
      ids: parsed.data.ids, action: parsed.data.action,
      assignedToId: parsed.data.assignedToId, assignedToTeam: parsed.data.assignedToTeam,
      tags: parsed.data.tags, reason: parsed.data.reason,
      ...(parsed.data.riskAcceptanceExpiresAt ? { riskAcceptanceExpiresAt: new Date(parsed.data.riskAcceptanceExpiresAt) } : {}),
    });
  }

  @Post("imports/preview")
  async importPreview(@Req() req: never, @CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = importSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.imports.preview(user, ws.id, { scanner: parsed.data.scanner, raw: parsed.data.payload });
  }

  @Get("imports")
  async importList(@Req() req: never, @CurrentUser() user: RequestUser) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.imports.list(ws.id);
  }

  @Post("imports/:id/commit")
  async importCommit(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = commitSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.imports.commit(user, ws.id, id, parsed.data.payload, parsed.data.scanId);
  }

  @Get("sla-policies")
  async slaPolicies(@Req() req: never, @CurrentUser() user: RequestUser) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.prisma.remediationSlaPolicy.findMany({ where: { workspaceId: ws.id }, orderBy: { createdAt: "asc" } });
  }

  @Post("sla-policies")
  async createSlaPolicy(@Req() req: never, @CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "TRIAGE_VULNERABILITIES");
    const parsed = slaPolicySchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    const row = await this.prisma.remediationSlaPolicy.create({
      data: {
        workspaceId: ws.id, name: parsed.data.name, createdBy: user.id,
        rules: { ...(parsed.data.byPriority ?? {}), ...(parsed.data.bySeverity ?? {}) } as never,
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: ws.id, action: "INTELLIGENCE_UPDATED", resourceType: "SLA_POLICY", resourceId: row.id, metadata: { name: row.name } });
    return row;
  }

  @Get("by-asset/:assetId/risk")
  async assetRisk(@Req() req: never, @CurrentUser() user: RequestUser, @Param("assetId") assetId: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.vulnerabilities.assetRisk(ws.id, assetId);
  }

  @Get(":id")
  async detail(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.vulnerabilities.detail(ws.id, id);
  }

  @Patch(":id")
  async transition(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = transitionSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.transition(user, ws.id, id, {
      to: parsed.data.lifecycleStatus as VmLifecycleStatus,
      reason: parsed.data.reason, reviewerId: parsed.data.reviewerId,
      ...(parsed.data.riskAcceptance ? { riskAcceptance: { approverId: parsed.data.riskAcceptance.approverId, expiresAt: new Date(parsed.data.riskAcceptance.expiresAt) } } : {}),
    });
  }

  @Post(":id/assign")
  async assign(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = assignSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.assign(user, ws.id, id, parsed.data);
  }

  @Post(":id/accept-risk")
  async acceptRisk(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = z.object({ reason: z.string().min(1).max(2000), expiresAt: z.string().datetime() }).safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.transition(user, ws.id, id, {
      to: "ACCEPTED_RISK", reason: parsed.data.reason,
      riskAcceptance: { approverId: user.id, expiresAt: new Date(parsed.data.expiresAt) },
    });
  }

  @Post(":id/false-positive")
  async falsePositive(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = z.object({ reason: z.string().min(1).max(2000) }).safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.transition(user, ws.id, id, { to: "FALSE_POSITIVE", reason: parsed.data.reason, reviewerId: user.id });
  }

  @Post(":id/comments")
  async comment(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = commentSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.addComment(user, ws.id, id, parsed.data.body);
  }

  @Post(":id/tags")
  async tags(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = tagsSchema.safeParse(body);
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.vulnerabilities.setTags(user, ws.id, id, parsed.data.tags);
  }

  @Post(":id/enrich")
  async enrich(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "TRIAGE_VULNERABILITIES");
    const result = await this.vulnerabilities.applyEnrichment(user, ws.id, id);
    return { finding: result.view, enrichment: result.enrichment, risk: result.risk };
  }

  @Post(":id/request-retest")
  async requestRetest(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(req, user);
    const parsed = z.object({ reason: z.string().max(2000).optional() }).safeParse(body ?? {});
    if (!parsed.success) throw new BadRequestException(parsed.error.issues.map((i) => i.message).join("; "));
    return this.retests.requestRetest(user, ws.id, id, parsed.data.reason);
  }

  @Get(":id/retests")
  async retestList(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.retests.listForFinding(ws.id, id);
  }

  @Get(":id/observations")
  async observations(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    await this.vulnerabilities.getFinding(ws.id, id);
    return this.prisma.findingObservation.findMany({ where: { findingId: id }, orderBy: { observedAt: "desc" } });
  }

  @Get(":id/history")
  async history(@Req() req: never, @CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(req, user);
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    await this.vulnerabilities.getFinding(ws.id, id);
    return this.prisma.findingHistory.findMany({ where: { findingId: id }, orderBy: { createdAt: "asc" } });
  }
}

@Controller("cves")
export class CvesController {
  constructor(private readonly intelligence: IntelligenceService, @Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get(":cveId")
  async cve(@Req() req: { headers: Record<string, string | string[] | undefined> }, @CurrentUser() user: RequestUser, @Param("cveId") cveId: string) {
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    const ws = await resolveWorkspace(this.prisma, user, req.headers["x-workspace-id"] as string | undefined).catch(() => null);
    return this.intelligence.cveDetail(cveId, ws?.id);
  }
}

@Controller("vulnerability-intelligence")
export class VulnerabilityIntelligenceController {
  constructor(private readonly intelligence: IntelligenceService) {}

  @Get()
  async states(@CurrentUser() user: RequestUser) {
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return { sources: await this.intelligence.syncStates() };
  }

  @Get(":cveId")
  async byCve(@CurrentUser() user: RequestUser, @Param("cveId") cveId: string) {
    requireVmPermission(user, "VIEW_VULNERABILITIES");
    return this.intelligence.cveDetail(cveId);
  }

  @Post("sync/:source")
  async sync(@CurrentUser() user: RequestUser, @Param("source") source: string) {
    requireVmPermission(user, "MANAGE_SCANNERS");
    if (!["NVD", "FIRST_EPSS", "CISA_KEV"].includes(source)) throw new BadRequestException("unknown intelligence source");
    return this.intelligence.runSync(source as "NVD" | "FIRST_EPSS" | "CISA_KEV");
  }
}
