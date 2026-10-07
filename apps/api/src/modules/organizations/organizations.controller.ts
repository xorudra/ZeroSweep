import { Controller, Get, Inject, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";

@Controller("organizations")
export class OrganizationsController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get("current")
  async current(@CurrentUser() user: RequestUser) {
    const org = await this.prisma.organization.findFirst({ where: { id: user.organizationId, deletedAt: null } });
    if (!org) throw new NotFoundException("Organization not found");
    return org;
  }
}
