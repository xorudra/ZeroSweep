import { Body, Controller, Get, Headers, Inject, Param, Patch, Post, Query } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { RemediationCasesService } from "./cases.service";
import { TriageService } from "./triage.service";
import { OwnershipService } from "./ownership.service";
import { RemediationSlaService } from "./sla.service";
import { RemediationPlansService } from "./plans.service";
import { RemediationTicketsService } from "./tickets.service";
import { RemediationVerificationService } from "./verification.service";
import { RemediationClosureService } from "./closure.service";
import { RemediationExceptionsService } from "./exceptions.service";
import { RemediationCampaignsService } from "./campaigns.service";
import { RemediationRegressionService } from "./regression.service";
import { RemediationAnalyticsService } from "./analytics.service";
import { RemediationAiService } from "./ai.service";
import { RemediationReportsService } from "./reports.service";
import { RemediationBulkService } from "./bulk.service";
import { RemediationTickService } from "./tick.service";

/**
 * Remediation API (Prompt 31 §118). Tenant resolution goes through the
 * shared resolveWorkspace guard; every state-changing endpoint
 * authorizes (§121 permission inside the service), validates the
 * transition through the guarded state machine, audits, and publishes
 * through the transactional outbox (§119).
 */
@Controller("remediation")
export class RemediationController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly cases: RemediationCasesService,
    private readonly triage: TriageService,
    private readonly ownership: OwnershipService,
    private readonly sla: RemediationSlaService,
    private readonly plans: RemediationPlansService,
    private readonly tickets: RemediationTicketsService,
    private readonly verification: RemediationVerificationService,
    private readonly closure: RemediationClosureService,
    private readonly exceptions: RemediationExceptionsService,
    private readonly campaigns: RemediationCampaignsService,
    private readonly regressions: RemediationRegressionService,
    private readonly analyticsService: RemediationAnalyticsService,
    private readonly ai: RemediationAiService,
    private readonly reports: RemediationReportsService,
    private readonly bulk: RemediationBulkService,
    private readonly tick: RemediationTickService,
  ) {}

  private async ws(user: RequestUser, headers: Record<string, string | string[] | undefined>) {
    return resolveWorkspace(this.prisma, user, headers["x-workspace-id"] as string | undefined);
  }

  // ---- dashboard / queue / search (§103/§104/§117) ----
  @Get("dashboard")
  async dashboard(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>) {
    const ws = await this.ws(user, headers);
    return this.cases.dashboard(ws.id);
  }

  @Get("queue")
  async queue(
    @CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>,
    @Query("status") status?: string, @Query("ownerId") ownerId?: string,
    @Query("teamId") teamId?: string, @Query("priority") priority?: string,
    @Query("severity") severity?: string, @Query("kev") kev?: string,
    @Query("assetId") assetId?: string, @Query("repositoryId") repositoryId?: string,
    @Query("cve") cve?: string, @Query("cwe") cwe?: string,
    @Query("verificationState") verificationState?: string,
    @Query("patchAvailable") patchAvailable?: string, @Query("search") search?: string,
    @Query("page") page?: string, @Query("pageSize") pageSize?: string,
  ) {
    const ws = await this.ws(user, headers);
    return this.cases.listQueue(ws.id, {
      status, ownerId, teamId, priority, severity, assetId, repositoryId, cve, cwe,
      verificationState, search,
      ...(kev !== undefined ? { kev: kev === "true" } : {}),
      ...(patchAvailable !== undefined ? { patchAvailable: patchAvailable === "true" } : {}),
      ...(page ? { page: Number(page) } : {}),
      ...(pageSize ? { pageSize: Number(pageSize) } : {}),
    });
  }

  @Post("search")
  async search(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Body() body: { query: string }) {
    const ws = await this.ws(user, headers);
    return this.ai.naturalLanguageSearch(user, ws.id, body.query);
  }

  // ---- SLA (§106/§118) ----
  @Get("sla")
  async slaDashboard(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>) {
    const ws = await this.ws(user, headers);
    return this.sla.dashboard(ws.id);
  }

  @Get("sla/policies")
  async slaPolicies(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>) {
    const ws = await this.ws(user, headers);
    return this.sla.listPolicies(ws.id);
  }

  @Post("sla/policies")
  async createSlaPolicy(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.sla.createPolicy(user, ws.id, body);
  }

  @Patch("sla/policies/:policyId")
  async updateSlaPolicy(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("policyId") policyId: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.sla.updatePolicy(user, ws.id, policyId, body);
  }

  // ---- campaigns (§118) ----
  @Get("campaigns")
  async listCampaigns(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>) {
    const ws = await this.ws(user, headers);
    return this.campaigns.listCampaigns(ws.id);
  }

  @Post("campaigns")
  async createCampaign(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.campaigns.createCampaign(user, ws.id, body);
  }

  @Get("campaigns/:campaignId")
  async campaign(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("campaignId") campaignId: string) {
    const ws = await this.ws(user, headers);
    const campaign = await this.campaigns.getCampaign(ws.id, campaignId);
    return { campaign, progress: await this.campaigns.progress(ws.id, campaignId) };
  }

  @Post("campaigns/:campaignId/cases")
  async addCampaignCase(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("campaignId") campaignId: string, @Body() body: { caseId: string }) {
    const ws = await this.ws(user, headers);
    return this.campaigns.addCase(user, ws.id, campaignId, body.caseId);
  }

  // ---- regressions (§118) ----
  @Get("regressions")
  async listRegressions(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Query("caseId") caseId?: string) {
    const ws = await this.ws(user, headers);
    return this.regressions.listRegressions(ws.id, caseId);
  }

  // ---- analytics / reports / bulk / tick ----
  @Get("analytics")
  async analytics(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Query("teamId") teamId?: string) {
    const ws = await this.ws(user, headers);
    return this.analyticsService.metrics(ws.id, { teamId });
  }

  @Get("analytics/teams")
  async teamAnalytics(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>) {
    const ws = await this.ws(user, headers);
    return this.analyticsService.teamMetrics(ws.id);
  }

  @Get("reports")
  async listReports(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>) {
    const ws = await this.ws(user, headers);
    return this.reports.list(ws.id);
  }

  @Post("reports")
  async generateReport(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Body() body: { type: string; campaignId?: string }) {
    const ws = await this.ws(user, headers);
    return this.reports.generate(user, ws.id, body);
  }

  @Get("reports/:reportId")
  async report(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("reportId") reportId: string) {
    const ws = await this.ws(user, headers);
    return this.reports.get(ws.id, reportId);
  }

  @Post("bulk")
  async bulkAction(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.bulk.bulk(user, ws.id, body);
  }

  @Post("tick")
  async runTick(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Body() body: { now?: string }) {
    const ws = await this.ws(user, headers);
    return this.tick.tick(user, ws.id, body?.now ? new Date(body.now) : new Date());
  }

  @Get("sbom/:purl/exposure")
  async sbomExposure(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("purl") purl: string) {
    const ws = await this.ws(user, headers);
    return this.campaigns.sbomExposure(ws.id, decodeURIComponent(purl));
  }

  // ---- cases (§118) ----
  @Post("findings/:findingId/case")
  async ensureCase(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("findingId") findingId: string) {
    const ws = await this.ws(user, headers);
    return this.cases.ensureCase(user, ws.id, findingId);
  }

  @Get(":id")
  async detail(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string) {
    const ws = await this.ws(user, headers);
    return this.cases.getCaseDetail(user, ws.id, id);
  }

  @Patch(":id")
  async transition(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.cases.transition(user, ws.id, id, body);
  }

  @Post(":id/triage")
  async doTriage(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.triage.triage(user, ws.id, id, body);
  }

  @Post(":id/assign")
  async assign(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.ownership.assign(user, ws.id, id, body);
  }

  @Get(":id/owner-suggestion")
  async ownerSuggestion(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string) {
    const ws = await this.ws(user, headers);
    return this.ownership.suggestOwner(ws.id, id);
  }

  @Post(":id/sla/assign")
  async assignSla(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string) {
    const ws = await this.ws(user, headers);
    return this.sla.assignSla(user, ws.id, id);
  }

  @Post(":id/sla/recalculate")
  async recalculateSla(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: { allowShorten?: boolean }) {
    const ws = await this.ws(user, headers);
    return this.sla.recalculate(user, ws.id, id, body ?? {});
  }

  @Post(":id/sla/pause")
  async pauseSla(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.sla.pauseSla(user, ws.id, id, body);
  }

  @Post(":id/sla/resume")
  async resumeSla(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string) {
    const ws = await this.ws(user, headers);
    return this.sla.resumeSla(user, ws.id, id);
  }

  @Post(":id/plan")
  async createPlan(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.plans.createPlan(user, ws.id, id, body);
  }

  @Post(":id/tickets")
  async createTicket(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: { provider: string; integrationId?: string }) {
    const ws = await this.ws(user, headers);
    return this.tickets.createTicket(user, ws.id, id, body);
  }

  @Post("work-items/:workItemId/retry")
  async retryTicket(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("workItemId") workItemId: string) {
    const ws = await this.ws(user, headers);
    return this.tickets.retryTicket(user, ws.id, workItemId);
  }

  @Post("work-items/:workItemId/sync")
  async syncTicket(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("workItemId") workItemId: string) {
    const ws = await this.ws(user, headers);
    return this.tickets.syncWorkItem(user, ws.id, workItemId);
  }

  @Post(":id/fix-claim")
  async fixClaim(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.tickets.recordFixClaim(user, ws.id, id, body);
  }

  @Post(":id/verify")
  async verify(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.verification.requestVerification(user, ws.id, id, body);
  }

  @Get(":id/verification-jobs")
  async verificationJobs(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string) {
    const ws = await this.ws(user, headers);
    return this.verification.listJobs(ws.id, id);
  }

  @Post(":id/verification/:jobId/observation")
  async observation(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Param("jobId") jobId: string, @Body() body: never) {
    const ws = await this.ws(user, headers);
    return this.verification.recordObservation(user, ws.id, id, jobId, body);
  }

  @Post(":id/verification/:jobId/sbom-reevaluate")
  async sbomReevaluate(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Param("jobId") jobId: string) {
    const ws = await this.ws(user, headers);
    return this.verification.reevaluateSbom(user, ws.id, id, jobId);
  }

  @Post(":id/close")
  async close(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: { reason: string }) {
    const ws = await this.ws(user, headers);
    return this.closure.closeCase(user, ws.id, id, body);
  }

  @Post(":id/exceptions")
  async createException(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: {
    type: string; reason: string; ownerId: string; expiresAt: string;
    scope?: Record<string, unknown>; compensatingControls?: unknown; reviewAt?: string;
  }) {
    const ws = await this.ws(user, headers);
    return this.exceptions.createException(user, ws.id, id, {
      type: body.type, reason: body.reason, ownerId: body.ownerId,
      expiresAt: new Date(body.expiresAt),
      ...(body.scope ? { scope: body.scope } : {}),
      ...(body.compensatingControls !== undefined ? { compensatingControls: body.compensatingControls } : {}),
      ...(body.reviewAt ? { reviewAt: new Date(body.reviewAt) } : {}),
    });
  }

  @Post(":id/exceptions/:exceptionId/approve")
  async approveException(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Param("exceptionId") exceptionId: string) {
    const ws = await this.ws(user, headers);
    return this.exceptions.approveException(user, ws.id, id, exceptionId);
  }

  @Post(":id/exceptions/:exceptionId/reject")
  async rejectException(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Param("exceptionId") exceptionId: string) {
    const ws = await this.ws(user, headers);
    return this.exceptions.rejectException(user, ws.id, id, exceptionId);
  }

  @Post(":id/ai")
  async aiAssist(@CurrentUser() user: RequestUser, @Headers() headers: Record<string, string>, @Param("id") id: string, @Body() body: { task: string; instruction?: string }) {
    const ws = await this.ws(user, headers);
    return this.ai.assist(user, ws.id, id, body);
  }
}
