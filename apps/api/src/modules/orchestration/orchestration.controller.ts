import { Controller, Get, Inject, NotFoundException, Param, Post, Query, Sse } from "@nestjs/common";
import { filter, map, type Observable } from "rxjs";
import { paginationSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { OrchestrationService } from "./orchestration.service";
import { ScanEventsService } from "./scan-events.service";

/**
 * Orchestration HTTP surface (Prompt 4 §46–§49, §26–§27).
 * No request body is accepted for plan/start: the backend builds the plan
 * from trusted state. There is deliberately NO execute/command route.
 */
@Controller()
export class OrchestrationController {
  constructor(
    private readonly orchestration: OrchestrationService,
    private readonly events: ScanEventsService,
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
  ) {}

  @Post("assessments/:id/plan")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER")
  async plan(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.orchestration.previewPlan(user, id);
  }

  @Post("assessments/:id/scans")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async start(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.orchestration.startScan(user, id);
  }

  @Get("scans/:id/details")
  async details(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.orchestration.getScanDetails(user, id);
  }

  @Get("scans/:id/events")
  async listEvents(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    const { page = 1, pageSize = 50 } = parseOrThrow(paginationSchema, query ?? {});
    await this.assertScanAccess(user, id);
    return this.events.list(id, page, pageSize);
  }

  /**
   * Live event stream (SSE). The scan is authorized against the caller's
   * workspace BEFORE subscribing (§41): another tenant's scan id is a 404,
   * never a stream of foreign events.
   */
  @Sse("scans/:id/stream")
  async stream(@CurrentUser() user: RequestUser, @Param("id") id: string): Promise<Observable<{ data: unknown }>> {
    await this.assertScanAccess(user, id);
    return this.events.streamFor(id).pipe(
      filter((event) => event.scanId === id),
      map((event) => ({ data: event })),
    );
  }

  @Get("admin/orchestration")
  @Roles("OWNER", "ADMIN")
  async ops(@CurrentUser() user: RequestUser) {
    return this.orchestration.opsOverview(user);
  }

  @Post("scans/:id/pause")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async pause(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.orchestration.pauseScan(user, id);
  }

  @Post("scans/:id/resume")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async resume(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.orchestration.resumeScan(user, id);
  }

  @Post("scans/:id/stop")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async stop(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.orchestration.emergencyStop(user, id);
  }

  private async assertScanAccess(user: RequestUser, scanId: string): Promise<void> {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id }, select: { id: true } });
    if (!scan) throw new NotFoundException("Scan not found");
  }
}
