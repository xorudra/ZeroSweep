import { Body, Controller, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { Inject } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { parseOrThrow } from "../../common/parse";
import {
  authorizeActiveTestingSchema, createOwnershipRuleSchema, createProgramSchema, createRootAssetSchema,
  easmAskSchema, generateReportSchema, patchCandidateSchema, patchProgramSchema, runDiscoverySchema,
  upsertPolicySchema, upsertServiceProfileSchema, verifyRootAssetSchema,
} from "./dto/schemas";
import { EasmProgramsService } from "./programs/programs.service";
import { EasmDiscoveryService } from "./discovery/discovery.service";
import { EasmAssetsService } from "./assets/assets.service";
import { EasmDriftService } from "./drift/drift.service";
import { EasmAnalyticsService } from "./analytics/analytics.service";
import { EasmAiService } from "./ai/ai.service";
import { EasmReportsService } from "./reports/reports.service";
import { EasmMonitoringService } from "./monitoring/monitoring.service";
import { easmPermissionsFor } from "./permissions";

/**
 * EASM API (Prompt 29 §115). Every route resolves the workspace
 * through the tenant guard first: a foreign workspace id is a 403,
 * a foreign record id inside the caller's workspace is a 404
 * (§148 cross-tenant discipline, same as SOC).
 */
@Controller("easm")
export class EasmController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly programs: EasmProgramsService,
    private readonly discovery: EasmDiscoveryService,
    private readonly assets: EasmAssetsService,
    private readonly drift: EasmDriftService,
    private readonly analytics: EasmAnalyticsService,
    private readonly ai: EasmAiService,
    private readonly reports: EasmReportsService,
    private readonly monitoring: EasmMonitoringService,
  ) {}

  private async ws(user: RequestUser, workspaceId?: string): Promise<string> {
    const workspace = await resolveWorkspace(this.prisma, user, workspaceId);
    return workspace.id as string;
  }

  @Get("dashboard")
  async dashboard(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("programId") programId?: string) {
    const ws = await this.ws(user, workspaceId);
    const [overview, trends] = await Promise.all([
      this.analytics.dashboard(user, ws, programId),
      this.analytics.trends(user, ws, programId),
    ]);
    return { permissions: easmPermissionsFor(user), overview, trends };
  }

  /* ------------------------------- programs -------------------------------- */

  @Get("programs")
  async listPrograms(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.programs.listPrograms(user, await this.ws(user, workspaceId));
  }

  @Post("programs")
  async createProgram(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.createProgram(user, await this.ws(user, workspaceId), parseOrThrow(createProgramSchema, body));
  }

  @Patch("programs/:id")
  async patchProgram(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.patchProgram(user, await this.ws(user, workspaceId), id, parseOrThrow(patchProgramSchema, body) as never);
  }

  @Get("programs/:id/roots")
  async listRoots(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.programs.listRootAssets(user, await this.ws(user, workspaceId), id);
  }

  @Post("programs/:id/roots")
  async addRoot(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.addRootAsset(user, await this.ws(user, workspaceId), id, parseOrThrow(createRootAssetSchema, body));
  }

  @Post("roots/:id/verify")
  async verifyRoot(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.verifyRootAsset(user, await this.ws(user, workspaceId), id, parseOrThrow(verifyRootAssetSchema, body));
  }

  @Post("roots/:id/authorize-active-testing")
  async authorizeActive(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.authorizeActiveTesting(user, await this.ws(user, workspaceId), id, parseOrThrow(authorizeActiveTestingSchema, body));
  }

  @Get("programs/:id/policy")
  async getPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.programs.getPolicy(user, await this.ws(user, workspaceId), id);
  }

  @Patch("programs/:id/policy")
  async upsertPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.upsertPolicy(user, await this.ws(user, workspaceId), id, parseOrThrow(upsertPolicySchema, body) as never);
  }

  @Patch("programs/:id/service-profile")
  async upsertServiceProfile(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.programs.upsertServiceProfile(user, await this.ws(user, workspaceId), id, parseOrThrow(upsertServiceProfileSchema, body));
  }

  /* ------------------------------- discovery ------------------------------- */

  @Post("programs/:id/discover")
  async discover(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = parseOrThrow(runDiscoverySchema, body ?? {});
    return this.discovery.runDiscovery(user, await this.ws(user, workspaceId), id, parsed as never);
  }

  @Get("programs/:id/runs")
  async listRuns(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.discovery.listRuns(user, await this.ws(user, workspaceId), id);
  }

  @Post("programs/:id/monitoring-schedule")
  async ensureSchedule(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined) {
    return this.monitoring.ensureSchedule(user, await this.ws(user, workspaceId), id);
  }

  @Post("monitoring/tick")
  async tick(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined) {
    return this.monitoring.tick(user, await this.ws(user, workspaceId));
  }

  /* --------------------------------- assets -------------------------------- */

  @Get("assets")
  async listAssets(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("programId") programId?: string, @Query("ownershipStatus") ownershipStatus?: string, @Query("exposureState") exposureState?: string, @Query("lifecycle") lifecycle?: string, @Query("type") type?: string) {
    return this.assets.listCandidates(user, await this.ws(user, workspaceId), { programId, ownershipStatus, exposureState, lifecycle, type });
  }

  @Get("candidates")
  async listCandidates(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("programId") programId?: string, @Query("status") status?: string, @Query("ownershipStatus") ownershipStatus?: string) {
    return this.assets.listCandidates(user, await this.ws(user, workspaceId), { programId, status, ownershipStatus });
  }

  @Get("unknown-assets")
  async unknownAssets(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("programId") programId?: string) {
    return this.assets.unknownQueue(user, await this.ws(user, workspaceId), programId);
  }

  @Get("assets/:id")
  async assetDetail(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.assets.candidateDetail(user, await this.ws(user, workspaceId), id);
  }

  @Patch("candidates/:id")
  async patchCandidate(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.assets.patchCandidate(user, await this.ws(user, workspaceId), id, parseOrThrow(patchCandidateSchema, body) as never);
  }

  @Post("candidates/:id/promote")
  async promote(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined) {
    return this.assets.promoteCandidate(user, await this.ws(user, workspaceId), id);
  }

  @Get("screenshots/:id")
  async screenshot(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.assets.getScreenshot(user, await this.ws(user, workspaceId), id);
  }

  /* ---------------------------- ownership rules ---------------------------- */

  @Get("ownership-rules")
  async listRules(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.assets.listOwnershipRules(user, await this.ws(user, workspaceId));
  }

  @Post("ownership-rules")
  async createRule(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.assets.createOwnershipRule(user, await this.ws(user, workspaceId), parseOrThrow(createOwnershipRuleSchema, body) as never);
  }

  /* ------------------------------ drift/baseline ---------------------------- */

  @Get("drift")
  async listDrift(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("programId") programId?: string, @Query("type") type?: string, @Query("severity") severity?: string, @Query("status") status?: string) {
    return this.drift.listDrift(user, await this.ws(user, workspaceId), { programId, type, severity, status });
  }

  @Post("drift/:id/acknowledge")
  async ackDrift(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined) {
    return this.drift.acknowledgeDrift(user, await this.ws(user, workspaceId), id);
  }

  @Get("programs/:id/baselines")
  async listBaselines(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.drift.listBaselines(user, await this.ws(user, workspaceId), id);
  }

  @Post("programs/:id/baselines")
  async createBaseline(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined) {
    return this.drift.createBaseline(user, await this.ws(user, workspaceId), id);
  }

  /* --------------------------- certificates/tech ---------------------------- */

  @Get("certificates")
  async certificates(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.analytics.certificates(user, await this.ws(user, workspaceId));
  }

  @Get("technologies")
  async technologies(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("programId") programId?: string) {
    return this.analytics.technologies(user, await this.ws(user, workspaceId), programId);
  }

  @Get("search")
  async search(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("q") q?: string) {
    return this.analytics.search(user, await this.ws(user, workspaceId), q ?? "");
  }

  /* ------------------------------- ai/reports ------------------------------ */

  @Post("ask")
  async ask(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.ai.ask(user, await this.ws(user, workspaceId), parseOrThrow(easmAskSchema, body));
  }

  @Post("reports")
  async generateReport(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.reports.generate(user, await this.ws(user, workspaceId), parseOrThrow(generateReportSchema, body));
  }

  @Get("reports")
  async listReports(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("type") type?: string) {
    return this.reports.list(user, await this.ws(user, workspaceId), type);
  }
}
