import { Body, Controller, Get, Inject, NotFoundException, Param, Post, Query } from "@nestjs/common";
import { z } from "zod";
import { paginationSchema } from "@zerosweep/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

const createReportSchema = z.object({ scanId: z.string().uuid(), format: z.enum(["PDF", "HTML", "JSON", "CSV"]).default("PDF") });

/** Report generation itself arrives in a later phase; records are created as
 *  PENDING and never fabricated as completed documents. */
@Controller("reports")
export class ReportsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const { page = 1, pageSize = 20 } = parseOrThrow(paginationSchema, query ?? {});
    const workspace = await resolveWorkspace(this.prisma, user);
    const where = { workspaceId: workspace.id } as never;
    const [items, total] = await Promise.all([
      this.prisma.report.findMany({ where, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.report.count({ where }),
    ]);
    return { items, total, page, pageSize };
  }

  @Post()
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createReportSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: data.scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    const report = await this.prisma.report.create({
      data: { workspaceId: workspace.id, scanId: scan.id, format: data.format as never, status: "PENDING", generatedBy: user.id },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "REPORT_GENERATED", resourceType: "Report", resourceId: report.id, metadata: { status: "PENDING" } });
    return { ...report, note: "Report queued as PENDING — rendering arrives in the reporting phase." };
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const report = await this.prisma.report.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!report) throw new NotFoundException("Report not found");
    return report;
  }
}
