import { Body, Controller, Get, Inject, NotFoundException, Param, Post, Query } from "@nestjs/common";
import { createScopeSchema, paginationSchema } from "@zerosweep/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { assertTargetInOrg, resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

@Controller("scopes")
export class ScopesController {
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
      this.prisma.scope.findMany({ where, orderBy: { createdAt: "desc" }, skip: (page - 1) * pageSize, take: pageSize }),
      this.prisma.scope.count({ where }),
    ]);
    return { items, total, page, pageSize };
  }

  @Post()
  @Roles("OWNER", "ADMIN", "SECURITY_ENGINEER")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createScopeSchema, body);
    const target = await assertTargetInOrg(this.prisma, user, data.targetId);
    const scope = await this.prisma.scope.create({
      data: { workspaceId: target.workspaceId, targetId: target.id, name: data.name, rules: data.rules as never },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: target.workspaceId, action: "SCOPE_CHANGED", resourceType: "Scope", resourceId: scope.id });
    return scope;
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scope = await this.prisma.scope.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!scope) throw new NotFoundException("Scope not found");
    return scope;
  }
}
