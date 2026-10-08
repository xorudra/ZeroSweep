import { Body, Controller, Delete, Get, Param, Patch, Post, Put, Query } from "@nestjs/common";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { Inject } from "@nestjs/common";
import {
  aiAskSchema, assessVendorSchema, collectEvidenceSchema, createAssessmentSchema, createAuditFindingSchema,
  createAuditSchema, createControlSchema, createEvidenceRequestSchema, createMappingSchema, createPolicySchema,
  createReportSchema, createReviewSchema, createRiskSchema, createScheduleSchema, createTreatmentSchema,
  createVendorSchema, decideAcceptanceSchema, grantAuditorAccessSchema, importFrameworkSchema,
  overrideFindingLinkSchema, recordSignalSchema, requestAcceptanceSchema, retentionSchema,
  reviewEvidenceSchema, reviewRequirementSchema, submitEvidenceRequestSchema, transitionPolicySchema,
  updateControlSchema, updateMatrixSchema, updateRiskSchema, uploadEvidenceSchema,
} from "./dto/schemas";
import { FrameworkService } from "./frameworks/framework.service";
import { ControlService } from "./controls/control.service";
import { EvidenceService } from "./evidence/evidence.service";
import { MonitoringService } from "./monitoring/monitoring.service";
import { AssessmentService } from "./assessments/assessment.service";
import { RiskService } from "./risks/risk.service";
import { PolicyService } from "./policies/policy.service";
import { GrcAuditService } from "./audits/audit.service";
import { VendorService } from "./vendors/vendor.service";
import { FindingLinkService } from "./findings/finding-link.service";
import { GrcAnalyticsService } from "./analytics/analytics.service";
import { GrcReportService } from "./reports/report.service";
import { GrcBackupService } from "./reports/backup.service";
import { AiGrcService } from "./ai/ai-grc.service";

/**
 * GRC API (Prompt 26 §109). Every handler resolves the caller's
 * workspace through the tenant helper — a request can only ever touch
 * its own organization's workspace (§140).
 */
@Controller("grc")
export class GrcController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly frameworks: FrameworkService,
    private readonly controls: ControlService,
    private readonly evidence: EvidenceService,
    private readonly monitoring: MonitoringService,
    private readonly assessments: AssessmentService,
    private readonly risks: RiskService,
    private readonly policies: PolicyService,
    private readonly audits: GrcAuditService,
    private readonly vendors: VendorService,
    private readonly findingLinks: FindingLinkService,
    private readonly analytics: GrcAnalyticsService,
    private readonly reports: GrcReportService,
    private readonly backup: GrcBackupService,
    private readonly ai: AiGrcService,
  ) {}

  private async ws(user: RequestUser) {
    return resolveWorkspace(this.prisma, user);
  }

  /* ------------------------------ frameworks ------------------------------ */
  @Get("frameworks")
  async listFrameworks(@CurrentUser() user: RequestUser) {
    return this.frameworks.listFrameworks(user);
  }

  @Post("frameworks/import")
  async importFramework(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.frameworks.importFramework(user, ws.id, parseOrThrow(importFrameworkSchema, body ?? {}));
  }

  @Post("frameworks/import-catalog/:key")
  async importCatalog(@CurrentUser() user: RequestUser, @Param("key") key: string) {
    const ws = await this.ws(user);
    return this.frameworks.importCatalogFramework(user, ws.id, key);
  }

  @Get("frameworks/:id")
  async getFramework(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.frameworks.getFramework(user, id);
  }

  @Patch("frameworks/:id/status")
  async setStatus(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: { status?: string }) {
    const ws = await this.ws(user);
    return this.frameworks.setFrameworkStatus(user, ws.id, id, body?.status ?? "");
  }

  /* ------------------------------- controls ------------------------------- */
  @Get("controls")
  async listControls(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.controls.listControls(user, ws.id);
  }

  @Post("controls")
  async createControl(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.controls.createControl(user, ws.id, parseOrThrow(createControlSchema, body ?? {}));
  }

  @Get("controls/:id")
  async getControl(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.controls.getControl(user, ws.id, id);
  }

  @Patch("controls/:id")
  async updateControl(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.controls.updateControl(user, ws.id, id, parseOrThrow(updateControlSchema, body ?? {}));
  }

  @Get("mappings")
  async listMappings(@CurrentUser() user: RequestUser, @Query("controlId") controlId?: string) {
    const ws = await this.ws(user);
    return this.controls.listMappings(user, ws.id, controlId);
  }

  @Post("mappings")
  async createMapping(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.controls.createMapping(user, ws.id, parseOrThrow(createMappingSchema, body ?? {}));
  }

  /* ------------------------------ monitoring ------------------------------ */
  @Post("controls/:id/signals")
  async recordSignal(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    const input = parseOrThrow(recordSignalSchema, { ...(body as object), controlId: id });
    return this.monitoring.recordSignal(user, ws.id, input);
  }

  @Get("controls/:id/signals")
  async listSignals(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.monitoring.listSignals(user, ws.id, id);
  }

  @Post("controls/:id/evaluate")
  async evaluate(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.monitoring.evaluate(user, ws.id, id, user.id);
  }

  @Get("controls/:id/evaluation")
  async getEvaluation(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.monitoring.getEvaluation(user, ws.id, id);
  }

  @Post("controls/:id/schedules")
  async createSchedule(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    const input = parseOrThrow(createScheduleSchema, { ...(body as object), controlId: id });
    return this.monitoring.createSchedule(user, ws.id, id, input.cron);
  }

  @Get("schedules")
  async listSchedules(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.monitoring.listSchedules(user, ws.id);
  }

  @Post("monitoring/reevaluate")
  async reevaluate(@CurrentUser() user: RequestUser, @Body() body: { signalKeys?: string[] }) {
    const ws = await this.ws(user);
    return this.monitoring.reevaluateForSignals(user, ws.id, body?.signalKeys ?? []);
  }

  @Get("drift")
  async listDrift(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.monitoring.listDrift(user, ws.id);
  }

  /* ------------------------------- evidence ------------------------------- */
  @Get("evidence")
  async listEvidence(@CurrentUser() user: RequestUser, @Query("controlId") controlId?: string) {
    const ws = await this.ws(user);
    return this.evidence.listEvidence(user, ws.id, controlId);
  }

  @Post("evidence")
  async collectEvidence(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.evidence.collect(user, ws.id, parseOrThrow(collectEvidenceSchema, body ?? {}));
  }

  @Post("evidence/upload")
  async uploadEvidence(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.evidence.upload(user, ws.id, parseOrThrow(uploadEvidenceSchema, body ?? {}));
  }

  @Post("evidence/:id/review")
  async reviewEvidence(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.evidence.review(user, ws.id, id, parseOrThrow(reviewEvidenceSchema, body ?? {}));
  }

  /* ----------------------------- assessments ------------------------------ */
  @Get("assessments")
  async listAssessments(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.assessments.listAssessments(user, ws.id);
  }

  @Post("assessments")
  async createAssessment(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.assessments.createAssessment(user, ws.id, parseOrThrow(createAssessmentSchema, body ?? {}));
  }

  @Get("assessments/:id")
  async getAssessment(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.assessments.getAssessment(user, ws.id, id);
  }

  @Post("assessments/:id/compute")
  async computeAssessment(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.assessments.computeResults(user, ws.id, id);
  }

  @Post("assessments/:id/complete")
  async completeAssessment(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.assessments.completeAssessment(user, ws.id, id);
  }

  @Post("assessments/:id/results/:resultId/review")
  async reviewResult(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("resultId") resultId: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.assessments.reviewRequirement(user, ws.id, id, resultId, parseOrThrow(reviewRequirementSchema, body ?? {}));
  }

  /* --------------------------------- risks -------------------------------- */
  @Get("risks/technical-exceptions")
  async technicalExceptions(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.risks.listTechnicalExceptions(user, ws.id);
  }

  @Put("risk-matrix")
  async updateMatrix(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.updateMatrix(user, ws.id, parseOrThrow(updateMatrixSchema, body ?? {}));
  }

  @Get("risks")
  async listRisks(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.risks.listRisks(user, ws.id);
  }

  @Post("risks")
  async createRisk(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.createRisk(user, ws.id, parseOrThrow(createRiskSchema, body ?? {}));
  }

  @Get("risks/:id")
  async getRisk(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.risks.getRisk(user, ws.id, id);
  }

  @Patch("risks/:id")
  async updateRisk(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.updateRisk(user, ws.id, id, parseOrThrow(updateRiskSchema, body ?? {}));
  }

  @Post("risks/:id/treatments")
  async createTreatment(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.createTreatment(user, ws.id, id, parseOrThrow(createTreatmentSchema, body ?? {}));
  }

  @Post("risks/:id/acceptances")
  async requestAcceptance(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.requestAcceptance(user, ws.id, id, parseOrThrow(requestAcceptanceSchema, body ?? {}));
  }

  @Post("risks/:id/acceptances/:acceptanceId/decide")
  async decideAcceptance(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("acceptanceId") acceptanceId: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.decideAcceptance(user, ws.id, id, acceptanceId, parseOrThrow(decideAcceptanceSchema, body ?? {}));
  }

  @Post("risks/:id/reviews")
  async createReview(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.risks.createReview(user, ws.id, id, parseOrThrow(createReviewSchema, body ?? {}));
  }

  /* -------------------------------- policies ------------------------------- */
  @Get("policies")
  async listPolicies(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.policies.listPolicies(user, ws.id);
  }

  @Post("policies")
  async createPolicy(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.policies.createPolicy(user, ws.id, parseOrThrow(createPolicySchema, body ?? {}));
  }

  @Post("policies/:id/transition")
  async transitionPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.policies.transitionPolicy(user, ws.id, id, parseOrThrow(transitionPolicySchema, body ?? {}));
  }

  @Post("policies/:id/acknowledge")
  async acknowledgePolicy(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.policies.acknowledge(user, ws.id, id);
  }

  @Get("retention")
  async getRetention(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.policies.getRetention(user, ws.id);
  }

  @Put("retention")
  async updateRetention(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.policies.updateRetention(user, ws.id, parseOrThrow(retentionSchema, body ?? {}));
  }

  /* --------------------------------- audits -------------------------------- */
  @Get("audits")
  async listAudits(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.audits.listAudits(user, ws.id);
  }

  @Post("audits")
  async createAudit(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.audits.createAudit(user, ws.id, parseOrThrow(createAuditSchema, body ?? {}));
  }

  @Post("audits/:id/requests")
  async createRequest(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.audits.createRequest(user, ws.id, id, parseOrThrow(createEvidenceRequestSchema, body ?? {}));
  }

  @Post("audits/:id/requests/:requestId/submit")
  async submitRequest(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("requestId") requestId: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.audits.submitRequest(user, ws.id, id, requestId, parseOrThrow(submitEvidenceRequestSchema, body ?? {}));
  }

  @Post("audits/:id/requests/:requestId/decide")
  async decideRequest(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("requestId") requestId: string, @Body() body: { decision?: "ACCEPTED" | "REJECTED" }) {
    const ws = await this.ws(user);
    return this.audits.decideRequest(user, ws.id, id, requestId, body?.decision ?? "ACCEPTED");
  }

  @Post("audits/:id/findings")
  async createAuditFinding(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.audits.createFinding(user, ws.id, id, parseOrThrow(createAuditFindingSchema, body ?? {}));
  }

  @Get("audits/:id/findings")
  async listAuditFindings(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.audits.listFindings(user, ws.id, id);
  }

  @Post("audits/:id/package")
  async generatePackage(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: { assessmentId?: string }) {
    const ws = await this.ws(user);
    return this.audits.generatePackage(user, ws.id, id, body?.assessmentId ?? "");
  }

  @Get("packages/:id/verify")
  async verifyPackage(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.audits.verifyPackageIntegrity(user, ws.id, id);
  }

  @Get("packages/:id/download")
  async downloadPackage(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.audits.downloadPackage(user, ws.id, id);
  }

  @Post("auditor-grants")
  async grantAccess(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.audits.grantAuditorAccess(user, ws.id, parseOrThrow(grantAuditorAccessSchema, body ?? {}));
  }

  @Get("auditor-grants")
  async listGrants(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.audits.listGrants(user, ws.id);
  }

  @Delete("auditor-grants/:id")
  async revokeGrant(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.audits.revokeAuditorAccess(user, ws.id, id);
  }

  /* --------------------------------- vendors -------------------------------- */
  @Get("vendors")
  async listVendors(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.vendors.listVendors(user, ws.id);
  }

  @Post("vendors")
  async createVendor(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.vendors.createVendor(user, ws.id, parseOrThrow(createVendorSchema, body ?? {}));
  }

  @Post("vendors/:id/assess")
  async assessVendor(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.vendors.assessVendor(user, ws.id, id, parseOrThrow(assessVendorSchema, body ?? {}));
  }

  /* ------------------------------ finding links ------------------------------ */
  @Get("findings/:findingId/control-suggestion")
  async suggestion(@CurrentUser() user: RequestUser, @Param("findingId") findingId: string) {
    const ws = await this.ws(user);
    return this.findingLinks.suggestForFinding(user, ws.id, findingId);
  }

  @Post("findings/:findingId/control-link")
  async linkFinding(@CurrentUser() user: RequestUser, @Param("findingId") findingId: string) {
    const ws = await this.ws(user);
    return this.findingLinks.linkFinding(user, ws.id, findingId);
  }

  @Post("findings/:findingId/control-override")
  async overrideLink(@CurrentUser() user: RequestUser, @Param("findingId") findingId: string, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.findingLinks.overrideLink(user, ws.id, findingId, parseOrThrow(overrideFindingLinkSchema, body ?? {}));
  }

  @Get("finding-links")
  async listLinks(@CurrentUser() user: RequestUser, @Query("controlId") controlId?: string) {
    const ws = await this.ws(user);
    return this.findingLinks.listLinks(user, ws.id, controlId);
  }

  /* ------------------------------- dashboards ------------------------------- */
  @Get("dashboard/compliance")
  async complianceDashboard(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.analytics.complianceDashboard(user, ws.id);
  }

  @Get("dashboard/framework/:id")
  async frameworkDashboard(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await this.ws(user);
    return this.analytics.frameworkDashboard(user, ws.id, id);
  }

  @Get("dashboard/risks")
  async riskDashboard(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.analytics.riskDashboard(user, ws.id);
  }

  @Get("dashboard/evidence")
  async evidenceDashboard(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.analytics.evidenceDashboard(user, ws.id);
  }

  /* --------------------------------- reports -------------------------------- */
  @Post("reports")
  async generateReport(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.reports.generateReport(user, ws.id, parseOrThrow(createReportSchema, body ?? {}));
  }

  @Get("reports")
  async listReports(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.reports.listReports(user, ws.id);
  }

  @Get("reports/:id/export")
  async exportReport(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query("format") format?: string) {
    const ws = await this.ws(user);
    return this.reports.exportReport(user, ws.id, id, format ?? "json");
  }

  /* ----------------------------------- AI ----------------------------------- */
  @Post("ai/ask")
  async aiAsk(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.ai.ask(user, ws.id, parseOrThrow(aiAskSchema, body ?? {}));
  }

  @Post("ai/search")
  async aiSearch(@CurrentUser() user: RequestUser, @Body() body: { query?: string }) {
    const ws = await this.ws(user);
    return this.ai.search(user, ws.id, body?.query ?? "");
  }

  /* ------------------------------- backup/restore ---------------------------- */
  @Post("backup/export")
  async exportBackup(@CurrentUser() user: RequestUser) {
    const ws = await this.ws(user);
    return this.backup.exportState(user, ws.id);
  }

  @Post("backup/restore")
  async restoreBackup(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await this.ws(user);
    return this.backup.restoreState(user, ws.id, body as never);
  }
}
