import { Body, Controller, Get, Inject, Param, Post } from "@nestjs/common";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { ClientPortalService } from "./client-portal.service";

/** §95–§100 admin side: clients, engagements, portal users, publications. */
@Controller("client-portal/admin")
export class ClientAdminController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly portal: ClientPortalService,
  ) {}

  private async ws(user: RequestUser): Promise<string> {
    return (await resolveWorkspace(this.prisma, user)).id;
  }

  @Get("clients")
  async clients(@CurrentUser() user: RequestUser) {
    return this.portal.listClients(user, await this.ws(user));
  }

  @Post("clients")
  async createClient(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    return this.portal.createClient(user, await this.ws(user), body as never);
  }

  @Get("engagements")
  async engagements(@CurrentUser() user: RequestUser) {
    return this.portal.listEngagementsAdmin(user, await this.ws(user));
  }

  @Post("engagements")
  async createEngagement(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    return this.portal.createEngagement(user, await this.ws(user), body as never);
  }

  @Post("portal-users")
  async bind(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    return this.portal.bindPortalUser(user, await this.ws(user), body as never);
  }

  @Post("engagements/:id/publish")
  async publish(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.portal.publishFinding(user, await this.ws(user), id, String(body.findingId ?? ""));
  }

  @Post("engagements/:id/unpublish")
  async unpublish(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.portal.unpublishFinding(user, await this.ws(user), id, String(body.findingId ?? ""));
  }
}

/** §98 portal routes — every handler resolves the caller's client
 *  binding first; there is no workspace parameter to abuse. */
@Controller("client")
export class ClientPortalController {
  constructor(private readonly portal: ClientPortalService) {}

  @Get("dashboard")
  async dashboard(@CurrentUser() user: RequestUser) {
    return this.portal.dashboard(user);
  }

  @Get("engagements")
  async engagements(@CurrentUser() user: RequestUser) {
    return this.portal.myEngagements(user);
  }

  @Get("engagements/:id/findings")
  async findings(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.portal.myFindings(user, id);
  }

  @Get("engagements/:id/findings/:findingId")
  async finding(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("findingId") findingId: string) {
    return this.portal.myFinding(user, id, findingId);
  }

  @Post("engagements/:id/findings/:findingId/comments")
  async comment(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("findingId") findingId: string, @Body() body: Record<string, unknown>) {
    return this.portal.comment(user, id, findingId, String(body.text ?? ""));
  }

  @Post("engagements/:id/findings/:findingId/fix-claimed")
  async claim(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("findingId") findingId: string, @Body() body: Record<string, unknown>) {
    return this.portal.claimFix(user, id, findingId, body.note as string | undefined);
  }

  @Post("engagements/:id/findings/:findingId/request-retest")
  async retest(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("findingId") findingId: string) {
    return this.portal.requestRetest(user, id, findingId);
  }

  @Get("engagements/:id/reports")
  async reports(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.portal.myReports(user, id);
  }

  @Post("engagements/:id/reports/:reportId/download")
  async download(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("reportId") reportId: string, @Body() body: Record<string, unknown>) {
    return this.portal.downloadReport(user, id, reportId, ((body.format as string) ?? "PDF") as never);
  }

  @Get("engagements/:id/export")
  async exportFindings(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.portal.exportFindings(user, id);
  }

  @Get("notifications")
  async notifications(@CurrentUser() user: RequestUser) {
    return this.portal.myNotifications(user);
  }

  @Post("notifications/:id/read")
  async read(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.portal.markNotificationRead(user, id);
  }
}

/** §106: anonymous-but-token-bound report access. The token IS the
 *  credential; failures are indistinguishable 404s. */
@Controller("shared-reports")
export class SharedReportController {
  constructor(private readonly portal: ClientPortalService) {}

  @Public()
  @Get(":token")
  async shared(@Param("token") token: string) {
    return this.portal.resolveSharedReport(token, "HTML");
  }

  @Public()
  @Post(":token/download")
  async download(@Param("token") token: string, @Body() body: Record<string, unknown>) {
    return this.portal.resolveSharedReport(token, ((body.format as string) ?? "PDF") as never);
  }
}
