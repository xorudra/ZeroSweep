import { Controller, Get, Inject, Param, Patch } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";

@Controller("notifications")
export class NotificationsController {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    return this.prisma.notification.findMany({ where: { userId: user.id }, orderBy: { createdAt: "desc" }, take: 50 });
  }

  @Patch(":id/read")
  async markRead(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    await this.prisma.notification.updateMany({ where: { id, userId: user.id }, data: { read: true } });
    return { read: true };
  }
}
