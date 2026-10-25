import { Body, Controller, Delete, Get, Header } from "@nestjs/common";
import { Inject } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, Roles, type RequestUser } from "../../common/decorators/auth.decorators";
import { UsersService } from "./users.service";

/** Users are always scoped to the caller's organization via memberships. */
@Controller("users")
export class UsersController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly users: UsersService,
  ) {}

  @Get()
  @Roles("OWNER", "ADMIN")
  async list(@CurrentUser() user: RequestUser) {
    const memberships = await this.prisma.membership.findMany({
      where: { organizationId: user.organizationId },
      include: { user: { select: { id: true, email: true, name: true, isActive: true, createdAt: true } } },
    });
    return memberships.map((m: { role: string; status: string; user: unknown }) => ({ role: m.role, status: m.status, user: m.user }));
  }

  /** Launch Safety F29: the caller's own personal-data export (JSON download). */
  @Get("me/export")
  @Header("Content-Type", "application/json")
  @Header("Content-Disposition", 'attachment; filename="zerosweep-data-export.json"')
  async exportMe(@CurrentUser() user: RequestUser) {
    return this.users.exportMe(user);
  }

  /** Launch Safety F28: password-confirmed deletion of the caller's OWN
   *  account only — the route takes no user id, by design. */
  @Delete("me")
  async deleteMe(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    return this.users.deleteMe(user, body);
  }
}
