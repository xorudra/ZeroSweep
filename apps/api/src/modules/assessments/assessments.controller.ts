import { BadRequestException, Body, Controller, ForbiddenException, Get, Inject, NotFoundException, Param, Post, Query } from "@nestjs/common";
import { createAssessmentSchema, paginationSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { assertTargetInOrg, resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

@Controller("assessments")
export class AssessmentsController {
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
      this.prisma.assessment.findMany({ where, include: { target: true }, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.assessment.count({ where }),
    ]);
    return { items, total, page, pageSize };
  }

  @Post()
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createAssessmentSchema, body);
    const target = await assertTargetInOrg(this.prisma, user, data.targetId);
    // Tenant-bind a client-supplied scopeId: the scope must belong to
    // this target in this workspace, otherwise a foreign scope's rules
    // would be disclosed via GET and used as scan authorization.
    if (data.scopeId) {
      const scope = await this.prisma.scope.findFirst({
        where: { id: data.scopeId, workspaceId: target.workspaceId, targetId: target.id },
      });
      if (!scope) throw new BadRequestException("scopeId does not belong to the target in this workspace");
    }
    const assessment = await this.prisma.assessment.create({
      data: {
        workspaceId: target.workspaceId, targetId: target.id, scopeId: data.scopeId,
        name: data.name, profile: data.profile as never, status: "PENDING_APPROVAL", createdBy: user.id,
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: target.workspaceId, action: "ASSESSMENT_CREATED", resourceType: "Assessment", resourceId: assessment.id });
    return assessment;
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const assessment = await this.prisma.assessment.findFirst({ where: { id, workspaceId: workspace.id }, include: { target: true, scope: true, scans: true } });
    if (!assessment) throw new NotFoundException("Assessment not found");
    return assessment;
  }

  @Post(":id/approve")
  @Roles("OWNER", "ADMIN")
  async approve(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const assessment = await this.prisma.assessment.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!assessment) throw new NotFoundException("Assessment not found");
    // Approval independence (security audit 2026-10-16 run-2): the
    // creator can never approve their own assessment — approval is the
    // second-person control the whole scan gate rests on.
    if (assessment.createdBy === user.id) throw new ForbiddenException("You cannot approve your own assessment — approval must come from another owner or admin");
    const updated = await this.prisma.assessment.update({ where: { id }, data: { status: "APPROVED", approvedBy: user.id } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "ASSESSMENT_APPROVED", resourceType: "Assessment", resourceId: id });
    return updated;
  }
}
