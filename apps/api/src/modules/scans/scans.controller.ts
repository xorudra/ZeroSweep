import { BadRequestException, Body, Controller, Get, Inject, NotFoundException, Param, Post, Query } from "@nestjs/common";
import { assertScanTransition, type ScanStatus } from "@dsrclone/types";
import { createScanSchema, paginationSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { QueueService } from "../../queue/queue.service";
import { AssetsService } from "../assets/assets.service";

/**
 * Scans are executions of approved assessments. Creating a scan records it as
 * QUEUED and enqueues an orchestration PLACEHOLDER job — in this phase no
 * security tool runs. A scan is refused unless the target is verified and the
 * assessment is approved: authorization is checked on the server, always.
 */
@Controller("scans")
export class ScansController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly queue: QueueService,
    private readonly assets: AssetsService,
  ) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const { page = 1, pageSize = 20 } = parseOrThrow(paginationSchema, query ?? {});
    const workspace = await resolveWorkspace(this.prisma, user);
    const where = { workspaceId: workspace.id } as never;
    const [items, total] = await Promise.all([
      this.prisma.scan.findMany({ where, include: { assessment: true }, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.scan.count({ where }),
    ]);
    return { items, total, page, pageSize };
  }

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createScanSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const assessment = await this.prisma.assessment.findFirst({
      where: { id: data.assessmentId, workspaceId: workspace.id }, include: { target: true },
    });
    if (!assessment) throw new NotFoundException("Assessment not found");
    if (assessment.status !== "APPROVED") throw new BadRequestException("Assessment must be APPROVED before a scan can be requested");
    // Approval independence (security audit 2026-10-16 run-2), mirroring
    // the orchestration gate: a self-approved assessment authorizes nothing.
    if (!assessment.approvedBy || assessment.approvedBy === assessment.createdBy || assessment.approvedBy === user.id) {
      throw new BadRequestException("Assessment approval must be independent: recorded, and granted by someone other than its creator or the scan requester");
    }
    if (!assessment.target.verified) throw new BadRequestException("Target ownership must be verified before a scan can be requested");
    const scan = await this.prisma.scan.create({
      data: { workspaceId: workspace.id, assessmentId: assessment.id, status: "QUEUED", requestedBy: user.id },
    });
    await this.prisma.scanStage.createMany({
      data: (["AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "PASSIVE_RECON", "ASSET_DISCOVERY", "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION"] as const).map((type) => ({ scanId: scan.id, type: type as never })),
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "SCAN_REQUESTED", resourceType: "Scan", resourceId: scan.id });
    const enqueued = await this.queue.enqueueOrchestrationPlaceholder({ scanId: scan.id, assessmentId: assessment.id, workspaceId: workspace.id });
    return { ...scan, queueEnqueued: enqueued, note: "Foundation phase: orchestration placeholder only — no security tool is executed." };
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id, workspaceId: workspace.id }, include: { stages: true, assessment: true, executions: true } });
    if (!scan) throw new NotFoundException("Scan not found");
    return scan;
  }

  /** Assets discovered by this scan (Prompt 5 §48). */
  @Get(":id/assets")
  async scanAssets(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.listScanAssets(user, id);
  }

  /** Endpoints discovered by this scan (Prompt 5 §48). */
  @Get(":id/endpoints")
  async scanEndpoints(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.listScanEndpoints(user, id);
  }

  /** Recon summary: inventory metrics, never vulnerability claims (§46). */
  @Get(":id/recon-summary")
  async reconSummary(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.reconSummary(user, id);
  }

  /** Web-surface summary (Prompt 6 §54/§55): content/parameter discovery
   *  metrics for this scan — endpoints, parameters, forms, tools. */
  @Get(":id/web-surface")
  async webSurface(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.assets.webSurfaceSummary(user, id);
  }

  /** Findings for one scan (Prompt 7 §38): canonical findings by default
   *  (duplicates merged into them), ordered by risk. */
  @Get(":id/findings")
  async scanFindings(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    const items = await this.prisma.finding.findMany({
      where: { scanId: id, workspaceId: workspace.id, duplicateOfId: null },
      orderBy: [{ riskScore: "desc" }, { createdAt: "desc" }], take: 200,
    });
    return { items, total: items.length };
  }

  /** Scan findings summary (§45) + tool contribution (§46), computed from
   *  this scan's REAL persisted findings only. */
  @Get(":id/findings-summary")
  async scanFindingsSummary(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    const all = await this.prisma.finding.findMany({ where: { scanId: id, workspaceId: workspace.id } });
    const canonical = all.filter((f) => !f.duplicateOfId);
    const bySeverity: Record<string, number> = {};
    for (const f of canonical) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    const byTool: Record<string, { total: number; contributed: number }> = {};
    for (const f of all) {
      for (const tool of f.sources ?? []) {
        byTool[tool] = byTool[tool] ?? { total: 0, contributed: 0 };
        byTool[tool].total++;
      }
    }
    for (const f of canonical) for (const tool of f.sources ?? []) byTool[tool]!.contributed++;
    return {
      totalFindings: all.length,
      uniqueFindings: canonical.length,
      duplicatesMerged: all.length - canonical.length,
      bySeverity,
      confirmed: canonical.filter((f) => f.verificationStatus === "CONFIRMED").length,
      likely: canonical.filter((f) => f.verificationStatus === "LIKELY").length,
      unverified: canonical.filter((f) => f.verificationStatus === "UNVERIFIED").length,
      falsePositives: canonical.filter((f) => f.status === "FALSE_POSITIVE").length,
      acceptedRisks: canonical.filter((f) => f.status === "ACCEPTED_RISK").length,
      byTool,
    };
  }

  @Post(":id/cancel")
  async cancel(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    if (scan.status === "CANCELLED") return scan; // cancellation is idempotent (Prompt 4 §26)
    try {
      assertScanTransition(scan.status as ScanStatus, "CANCELLING");
    } catch {
      throw new BadRequestException(`Scan in status ${scan.status} cannot be cancelled`);
    }
    // CANCELLING -> cancel pending stages -> CANCELLED. Running executions
    // observe the CANCELLED scan in the worker and stop cooperatively.
    await this.prisma.scan.update({ where: { id }, data: { status: "CANCELLING" } });
    await this.prisma.scanStage.updateMany({
      where: { scanId: id, status: { in: ["PENDING", "BLOCKED", "READY", "QUEUED"] as never } },
      data: { status: "CANCELLED" },
    });
    await (this.prisma.scanEvent?.create({
      data: { scanId: id, workspaceId: workspace.id, type: "scan.cancelled", payload: {} as never },
    }) ?? Promise.resolve()).catch(() => undefined);
    const updated = await this.prisma.scan.update({ where: { id }, data: { status: "CANCELLED", completedAt: new Date() } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "SCAN_CANCELLED", resourceType: "Scan", resourceId: id });
    return updated;
  }
}
