import { Body, Controller, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { Inject } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { parseOrThrow } from "../../common/parse";
import {
  addCommunicationSchema, addEvidenceSchema, addIndicatorSchema, addTimelineEntrySchema,
  advancePlaybookSchema, approveActionSchema, createCaseSchema, createDetectionRuleSchema,
  createIncidentSchema, createIntelSourceSchema, createSuppressionSchema, createTelemetrySourceSchema,
  importIntelSchema, ingestTelemetrySchema, patchAlertSchema, patchIncidentSchema, proposeActionSchema,
  ruleStatusSchema, socAskSchema, startPlaybookSchema, testRuleSchema, triageAlertSchema,
  updateDetectionRuleSchema, upsertPirSchema,
} from "./dto/schemas";
import { TelemetryService } from "./telemetry/telemetry.service";
import { IngestionCoordinator } from "./telemetry/ingestion-coordinator.service";
import { DetectionService } from "./detections/detection.service";
import { AlertService } from "./alerts/alert.service";
import { IncidentService } from "./incidents/incident.service";
import { IntelService } from "./threat-intelligence/intel.service";
import { SocCorrelationService } from "./correlation/soc-correlation.service";
import { ResponseService } from "./response/response.service";
import { PlaybookService } from "./playbooks/playbook.service";
import { SocAnalyticsService } from "./analytics/soc-analytics.service";
import { SocHealthService } from "./health/soc-health.service";
import { SocSiemService } from "./siem/soc-siem.service";
import { SocAiService } from "./ai/soc-ai.service";
import { socPermissionsFor } from "./permissions";

/**
 * SOC API (Prompt 28 §124 + the module's own surfaces). Every route
 * resolves the workspace through the tenant guard first: a foreign
 * workspace id is a 403, a foreign record id inside the caller's
 * workspace is a 404 (§154–§156).
 */
@Controller("soc")
export class SocController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly telemetry: TelemetryService,
    private readonly ingestion: IngestionCoordinator,
    private readonly detections: DetectionService,
    private readonly alerts: AlertService,
    private readonly incidents: IncidentService,
    private readonly intel: IntelService,
    private readonly correlation: SocCorrelationService,
    private readonly response: ResponseService,
    private readonly playbooks: PlaybookService,
    private readonly analytics: SocAnalyticsService,
    private readonly health: SocHealthService,
    private readonly siem: SocSiemService,
    private readonly ai: SocAiService,
  ) {}

  private async ws(user: RequestUser, workspaceId?: string): Promise<string> {
    const workspace = await resolveWorkspace(this.prisma, user, workspaceId);
    return workspace.id as string;
  }

  /* ------------------------------- dashboard ------------------------------- */

  @Get("dashboard")
  async dashboard(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    const ws = await this.ws(user, workspaceId);
    const [overview, telemetryHealth] = await Promise.all([
      this.analytics.overview(user, ws),
      this.health.telemetryHealth(user, ws),
    ]);
    return { permissions: socPermissionsFor(user), overview, telemetryHealth };
  }

  @Get("analytics")
  async socAnalytics(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.analytics.overview(user, await this.ws(user, workspaceId));
  }

  /* ------------------------------- telemetry ------------------------------- */

  @Post("telemetry/sources")
  async createSource(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.telemetry.createSource(user, await this.ws(user, workspaceId), parseOrThrow(createTelemetrySourceSchema, body));
  }

  @Get("telemetry/sources")
  async listSources(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.telemetry.listSources(user, await this.ws(user, workspaceId));
  }

  @Post("telemetry/ingest")
  async ingest(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = parseOrThrow(ingestTelemetrySchema, body);
    return this.ingestion.ingestAndProcess(user, await this.ws(user, workspaceId), parsed.auth, parsed.events);
  }

  @Get("telemetry/events")
  async listEvents(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("source") source?: string, @Query("eventCategory") eventCategory?: string, @Query("assetId") assetId?: string, @Query("identityReference") identityReference?: string) {
    return this.telemetry.listEvents(user, await this.ws(user, workspaceId), { source, eventCategory, assetId, identityReference });
  }

  @Get("telemetry/health")
  async telemetryHealth(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.health.telemetryHealth(user, await this.ws(user, workspaceId));
  }

  @Post("evaluate")
  async evaluate(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.health.evaluate(user, await this.ws(user, workspaceId));
  }

  /* ------------------------------ detections ------------------------------ */

  @Get("detections")
  async listDetections(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.detections.listRules(user, await this.ws(user, workspaceId));
  }

  @Post("detections")
  async createDetection(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.detections.createRule(user, await this.ws(user, workspaceId), parseOrThrow(createDetectionRuleSchema, body) as never);
  }

  @Post("detections/seed-templates")
  async seedTemplates(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.detections.seedTemplates(user, await this.ws(user, workspaceId));
  }

  @Get("detections/coverage")
  async coverage(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.detections.coverage(user, await this.ws(user, workspaceId));
  }

  @Get("detections/health")
  async detectionHealth(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.detections.health(user, await this.ws(user, workspaceId));
  }

  @Get("detections/:id")
  async getDetection(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.detections.getRule(user, await this.ws(user, workspaceId), id);
  }

  @Patch("detections/:id")
  async updateDetection(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.detections.updateRule(user, await this.ws(user, workspaceId), id, parseOrThrow(updateDetectionRuleSchema, body) as never);
  }

  @Post("detections/:id/status")
  async setDetectionStatus(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = parseOrThrow(ruleStatusSchema, body);
    return this.detections.setRuleStatus(user, await this.ws(user, workspaceId), id, parsed.status);
  }

  @Post("detections/:id/test")
  async testDetection(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = parseOrThrow(testRuleSchema, body);
    return this.detections.testRule(user, await this.ws(user, workspaceId), id, parsed.events as never);
  }

  /* -------------------------------- alerts -------------------------------- */

  @Get("alerts")
  async listAlerts(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("status") status?: string, @Query("priority") priority?: string, @Query("severity") severity?: string, @Query("ruleId") ruleId?: string, @Query("assetId") assetId?: string, @Query("identityReference") identityReference?: string, @Query("indicatorId") indicatorId?: string) {
    return this.alerts.listAlerts(user, await this.ws(user, workspaceId), { status, priority, severity, ruleId, assetId, identityReference, indicatorId });
  }

  @Get("alerts/:id")
  async getAlert(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.alerts.getAlertDetail(user, await this.ws(user, workspaceId), id);
  }

  @Patch("alerts/:id")
  async patchAlert(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.alerts.patchAlert(user, await this.ws(user, workspaceId), id, parseOrThrow(patchAlertSchema, body));
  }

  @Post("alerts/:id/triage")
  async triageAlert(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.alerts.triageAlert(user, await this.ws(user, workspaceId), id, parseOrThrow(triageAlertSchema, body));
  }

  @Post("alerts/:id/escalate")
  async escalateAlert(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = (body ?? {}) as { title?: string };
    return this.incidents.escalateAlert(user, await this.ws(user, workspaceId), id, parsed);
  }

  @Get("suppressions")
  async listSuppressions(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.alerts.listSuppressions(user, await this.ws(user, workspaceId));
  }

  @Post("suppressions")
  async createSuppression(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.alerts.createSuppression(user, await this.ws(user, workspaceId), parseOrThrow(createSuppressionSchema, body));
  }

  /* ------------------------------- incidents ------------------------------- */

  @Get("incidents")
  async listIncidents(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("status") status?: string, @Query("priority") priority?: string) {
    return this.incidents.listIncidents(user, await this.ws(user, workspaceId), { status, priority });
  }

  @Post("incidents")
  async createIncident(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.incidents.createIncident(user, await this.ws(user, workspaceId), parseOrThrow(createIncidentSchema, body) as never);
  }

  @Get("incidents/:id")
  async getIncident(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.incidents.getIncidentDetail(user, await this.ws(user, workspaceId), id);
  }

  @Patch("incidents/:id")
  async patchIncident(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.incidents.patchIncident(user, await this.ws(user, workspaceId), id, parseOrThrow(patchIncidentSchema, body) as never);
  }

  @Get("incidents/:id/graph")
  async incidentGraph(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.incidents.incidentGraph(user, await this.ws(user, workspaceId), id);
  }

  @Post("incidents/:id/timeline")
  async addTimeline(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = parseOrThrow(addTimelineEntrySchema, body);
    return this.incidents.addTimelineEntry(user, await this.ws(user, workspaceId), id, {
      entryType: parsed.entryType ?? "ANALYST_NOTE", summary: parsed.summary, amendsEntryId: parsed.amendsEntryId,
    });
  }

  @Post("incidents/:id/evidence")
  async addEvidence(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.incidents.addEvidence(user, await this.ws(user, workspaceId), id, parseOrThrow(addEvidenceSchema, body) as never);
  }

  @Get("incidents/:id/evidence/:evidenceId")
  async getEvidence(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("evidenceId") evidenceId: string, @Query("workspaceId") workspaceId?: string) {
    return this.incidents.getEvidence(user, await this.ws(user, workspaceId), id, evidenceId);
  }

  @Post("incidents/:id/evidence/:evidenceId/verify")
  async verifyEvidence(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("evidenceId") evidenceId: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = (body ?? {}) as { content?: string };
    return this.incidents.verifyEvidence(user, await this.ws(user, workspaceId), id, evidenceId, parsed.content ?? "");
  }

  @Post("incidents/:id/communications")
  async addCommunication(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.incidents.addCommunication(user, await this.ws(user, workspaceId), id, parseOrThrow(addCommunicationSchema, body) as never);
  }

  @Post("incidents/:id/pir")
  async upsertPir(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.incidents.upsertPir(user, await this.ws(user, workspaceId), id, parseOrThrow(upsertPirSchema, body) as never);
  }

  @Post("incidents/:id/reports")
  async generateReport(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = (body ?? {}) as { type?: string };
    const type = parsed.type ?? "INCIDENT_REPORT";
    return this.incidents.generateReport(user, await this.ws(user, workspaceId), id, type);
  }

  /* --------------------------------- cases --------------------------------- */

  @Get("cases")
  async listCases(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.incidents.listCases(user, await this.ws(user, workspaceId));
  }

  @Post("cases")
  async createCase(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.incidents.createCase(user, await this.ws(user, workspaceId), parseOrThrow(createCaseSchema, body) as never);
  }

  @Post("cases/:id/escalate")
  async escalateCase(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.incidents.escalateCase(user, await this.ws(user, workspaceId), id);
  }

  /* --------------------------- threat intelligence --------------------------- */

  @Get("threat-intelligence")
  async threatIntelligence(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("q") q?: string, @Query("type") type?: string, @Query("status") status?: string) {
    const ws = await this.ws(user, workspaceId);
    const [sources, indicators, matches] = await Promise.all([
      this.intel.listSources(user, ws),
      this.intel.searchIndicators(user, ws, { q, type, status }),
      this.intel.listMatches(user, ws, {}),
    ]);
    return { sources, indicators, recentMatches: matches };
  }

  @Get("indicators")
  async indicators(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("q") q?: string, @Query("type") type?: string, @Query("status") status?: string, @Query("minConfidence") minConfidence?: string) {
    return this.intel.searchIndicators(user, await this.ws(user, workspaceId), {
      q, type, status, minConfidence: minConfidence ? Number(minConfidence) : undefined,
    });
  }

  @Post("indicators")
  async addIndicator(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.intel.addIndicator(user, await this.ws(user, workspaceId), parseOrThrow(addIndicatorSchema, body) as never);
  }

  @Post("intel-sources")
  async createIntelSource(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.intel.createSource(user, await this.ws(user, workspaceId), parseOrThrow(createIntelSourceSchema, body) as never);
  }

  @Post("intel-sources/:id/import")
  async importIntel(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.intel.importIndicators(user, await this.ws(user, workspaceId), id, parseOrThrow(importIntelSchema, body) as never);
  }

  @Post("intel-sources/:id/sync")
  async syncIntel(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.intel.syncSource(user, await this.ws(user, workspaceId), id);
  }

  @Get("indicator-matches")
  async indicatorMatches(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string, @Query("indicatorId") indicatorId?: string) {
    return this.intel.listMatches(user, await this.ws(user, workspaceId), { indicatorId });
  }

  /* ------------------------------- correlation ------------------------------ */

  @Get("correlation/signals")
  async correlationSignals(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.correlation.listPlatformSignals(await this.ws(user, workspaceId));
  }

  /* -------------------------------- response -------------------------------- */

  @Get("response-actions")
  async responseCatalog(@CurrentUser() user: RequestUser) {
    return this.response.catalog(user);
  }

  @Post("incidents/:id/actions")
  async proposeAction(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.response.propose(user, await this.ws(user, workspaceId), id, parseOrThrow(proposeActionSchema, body));
  }

  @Post("response-actions/:id/approve")
  async approveAction(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    await this.ws(user, workspaceId);
    return this.response.approve(user, await this.ws(user, workspaceId), id, parseOrThrow(approveActionSchema, body));
  }

  @Post("response-actions/:id/execute")
  async executeAction(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.response.execute(user, await this.ws(user, workspaceId), id);
  }

  /* -------------------------------- playbooks ------------------------------- */

  @Get("playbooks")
  async listPlaybooks(@CurrentUser() user: RequestUser) {
    return this.playbooks.templates(user);
  }

  @Post("incidents/:id/playbooks")
  async startPlaybook(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = parseOrThrow(startPlaybookSchema, body);
    return this.playbooks.start(user, await this.ws(user, workspaceId), id, parsed.playbookKey);
  }

  @Get("incidents/:id/playbook-runs")
  async playbookRuns(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId?: string) {
    return this.playbooks.listRuns(user, await this.ws(user, workspaceId), id);
  }

  @Post("playbook-runs/:id/advance")
  async advancePlaybook(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.playbooks.advance(user, await this.ws(user, workspaceId), id, parseOrThrow(advancePlaybookSchema, body));
  }

  /* ---------------------------------- SIEM ---------------------------------- */

  @Get("siem-profiles")
  async siemProfiles(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId?: string) {
    return this.siem.listProfiles(user, await this.ws(user, workspaceId));
  }

  @Post("siem/forward")
  async siemForward(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    const parsed = (body ?? {}) as { integrationId: string; kind: "ALERT" | "INCIDENT"; resourceId: string; format?: string };
    return this.siem.forward(user, await this.ws(user, workspaceId), parsed);
  }

  /* ----------------------------------- AI ----------------------------------- */

  @Post("ai/ask")
  async aiAsk(@CurrentUser() user: RequestUser, @Query("workspaceId") workspaceId: string | undefined, @Body() body: unknown) {
    return this.ai.ask(user, await this.ws(user, workspaceId), parseOrThrow(socAskSchema, body));
  }
}
