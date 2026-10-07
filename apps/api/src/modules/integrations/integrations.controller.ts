import { Body, Controller, Get, Inject, Post } from "@nestjs/common";
import { z } from "zod";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";

const createIntegrationSchema = z.object({
  type: z.enum(["DEFECTDOJO", "FARADAY", "DRADIS", "PLEXTRAC", "SERPICO", "SHODAN", "CENSYS", "CUSTOM"]),
  name: z.string().min(1).max(200),
  // Non-secret configuration only. API keys belong in Credentials as secret
  // references — never inline here.
  config: z.record(z.union([z.string(), z.number(), z.boolean()])).optional(),
  enabled: z.boolean().default(false),
});

@Controller("integrations")
export class IntegrationsController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.integration.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" } });
  }

  @Post()
  @Roles("OWNER", "ADMIN")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createIntegrationSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.integration.create({
      data: { workspaceId: workspace.id, type: data.type as never, name: data.name, config: data.config as never, enabled: data.enabled },
    });
  }
}
