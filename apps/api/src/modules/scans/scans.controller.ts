import { BadRequestException, Body, Controller, Get, Inject, NotFoundException, Param, Post, Query } from "@nestjs/common";
import { assertScanTransition, type ScanStatus } from "@dsrclone/types";
import { createScanSchema, paginationSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
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
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createScanSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const assessment = await this.prisma.assessment.findFirst({
      where: { id: data.assessmentId, workspaceId: workspace.id }, include: { target: true },
    });
    if (!assessment) throw new NotFoundException("Assessment not found");
    if (assessment.status !== "APPROVED") throw new BadRequestException("Assessment must be APPROVED before a scan can be requested");
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

  @Post(":id/cancel")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
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
