import { Body, Controller, Get, Inject, NotFoundException, Param, Patch, Query } from "@nestjs/common";
import { z } from "zod";
import { FINDING_STATUSES } from "@dsrclone/types";
import { paginationSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";

const updateFindingSchema = z.object({
  status: z.enum(FINDING_STATUSES).optional(),
  verificationStatus: z.enum(["UNVERIFIED", "LIKELY", "CONFIRMED", "REJECTED"]).optional(),
});

/** Findings are only ever created by the worker pipeline (later phases) from
 *  normalized scanner output — never invented by the API. */
@Controller("findings")
export class FindingsController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const { page = 1, pageSize = 20 } = parseOrThrow(paginationSchema, query ?? {});
    const workspace = await resolveWorkspace(this.prisma, user);
    const where = { workspaceId: workspace.id } as never;
    const [items, total] = await Promise.all([
      this.prisma.finding.findMany({ where, include: { evidence: true, references: true }, orderBy: [{ severity: "asc" }, { createdAt: "desc" }], skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.finding.count({ where }),
    ]);
    return { items, total, page, pageSize };
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const finding = await this.prisma.finding.findFirst({ where: { id, workspaceId: workspace.id }, include: { evidence: true, references: true } });
    if (!finding) throw new NotFoundException("Finding not found");
    return finding;
  }

  @Patch(":id")
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST")
  async update(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const data = parseOrThrow(updateFindingSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const finding = await this.prisma.finding.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!finding) throw new NotFoundException("Finding not found");
    return this.prisma.finding.update({ where: { id }, data: data as never });
  }
}
