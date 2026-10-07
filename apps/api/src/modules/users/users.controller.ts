import { Controller, Get } from "@nestjs/common";
import { Inject } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";

/** Users are always scoped to the caller's organization via memberships. */
@Controller("users")
export class UsersController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get()
  @Roles("OWNER", "ADMIN")
  async list(@CurrentUser() user: RequestUser) {
    const memberships = await this.prisma.membership.findMany({
      where: { organizationId: user.organizationId },
      include: { user: { select: { id: true, email: true, name: true, isActive: true, createdAt: true } } },
    });
    return memberships.map((m: { role: string; status: string; user: unknown }) => ({ role: m.role, status: m.status, user: m.user }));
  }
}
