import { Body, Controller, Get, Inject, Post } from "@nestjs/common";
import { z } from "zod";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";

const createWorkspaceSchema = z.object({ name: z.string().min(1).max(200) });

@Controller("workspaces")
export class WorkspacesController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    return this.prisma.workspace.findMany({ where: { organizationId: user.organizationId, deletedAt: null }, orderBy: { createdAt: "asc" } });
  }

  @Post()
  @Roles("OWNER", "ADMIN")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createWorkspaceSchema, body);
    return this.prisma.workspace.create({ data: { organizationId: user.organizationId, name: data.name } });
  }
}
