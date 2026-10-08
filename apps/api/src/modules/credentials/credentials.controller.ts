import { Body, Controller, Delete, Get, Inject, NotFoundException, Param, Post } from "@nestjs/common";
import { createCredentialSchema } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";

/**
 * Credentials are METADATA ONLY: name, type, provider and a reference into a
 * secret manager. Secret values are never accepted, stored in these columns,
 * logged, or returned by any API response.
 */
@Controller("credentials")
export class CredentialsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  @Get()
  @Roles("OWNER", "ADMIN")
  async list(@CurrentUser() user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.credential.findMany({
      where: { workspaceId: workspace.id },
      select: { id: true, name: true, type: true, provider: true, secretReference: true, createdBy: true, createdAt: true, updatedAt: true },
      orderBy: { createdAt: "desc" },
    });
  }

  @Post()
  @Roles("OWNER", "ADMIN")
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const data = parseOrThrow(createCredentialSchema, body);
    const workspace = await resolveWorkspace(this.prisma, user);
    const credential = await this.prisma.credential.create({
      data: { workspaceId: workspace.id, name: data.name, type: data.type as never, provider: data.provider, secretReference: data.secretReference, createdBy: user.id },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id, action: "CREDENTIAL_CREATED", resourceType: "Credential", resourceId: credential.id, metadata: { provider: data.provider } });
    return credential;
  }

  @Delete(":id")
  @Roles("OWNER", "ADMIN")
  async remove(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const credential = await this.prisma.credential.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!credential) throw new NotFoundException("Credential not found");
    await this.prisma.credential.delete({ where: { id } });
    return { deleted: true };
  }
}
