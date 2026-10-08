import { Inject, Injectable } from "@nestjs/common";
import { GRC_DISCLAIMER, coverageMetrics, evidenceFreshness } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireGrcPermission } from "../permissions";
import { ControlService } from "../controls/control.service";

/**
 * GRC dashboards + coverage metrics (Prompt 26 §76–§83). Every number
 * is computed from live workspace records; the headline metric is
 * labelled "Assessment Coverage / Control Status" — never a
 * certification score (§82).
 */
@Injectable()
export class GrcAnalyticsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly controls: ControlService,
  ) {}

  async complianceDashboard(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    await this.controls.ensureCatalog(user, workspaceId);
    const frameworks = await this.prisma.complianceFramework.findMany({ orderBy: { key: "asc" } });
    const assessments = await this.prisma.complianceAssessment.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" },
    });
    const controls = await this.prisma.securityControl.findMany({ where: { workspaceId } });
    const evaluations = await this.prisma.controlEvaluation.findMany({
      where: { workspaceId }, orderBy: { evaluatedAt: "desc" }, take: 1000,
    });
    const latestByControl = new Map<string, string>();
    for (const e of evaluations) if (!latestByControl.has(e.controlId)) latestByControl.set(e.controlId, e.result);
    const failedControls = [...latestByControl.entries()].filter(([, r]) => r === "FAIL").map(([id]) => id);

    const now = new Date();
    const evidence = await this.prisma.complianceEvidence.findMany({ where: { workspaceId }, take: 2000 });
    let staleEvidence = 0;
    for (const ev of evidence) {
      const policy = await this.prisma.evidenceFreshnessPolicy.findFirst({ where: { workspaceId, controlId: ev.controlId } });
      const status = evidenceFreshness(new Date(ev.collectedAt).toISOString(), policy ?? { staleAfterDays: 335, expireAfterDays: 400 }, now, ev.status as never);
      if (status === "STALE" || status === "EXPIRED") staleEvidence++;
    }
    const exceptions = await this.prisma.riskException.count({ where: { workspaceId, status: "PENDING" } });
    const risks = await this.prisma.riskRecord.findMany({ where: { workspaceId } });
    const upcomingReviews = risks.filter((r) => r.reviewDate && new Date(r.reviewDate).getTime() > now.getTime()
      && new Date(r.reviewDate).getTime() - now.getTime() < 31 * 86_400_000).length;

    // Coverage metrics (§83) from the most recent completed assessment.
    const latestCompleted = assessments.find((a) => a.status === "COMPLETED" || a.status === "READY_FOR_REVIEW");
    let coverage = coverageMetrics({
      requirementsTotal: 0, requirementsAssessed: 0, controlsTotal: controls.length,
      controlsImplemented: controls.filter((c) => c.implementationStatus === "IMPLEMENTED").length,
      controlsTested: latestByControl.size,
      automatedControls: 0, evidenceCurrent: evidence.length - staleEvidence, evidenceTotal: evidence.length,
      manualEvidencePending: evidence.filter((e) => e.reviewStatus === "PENDING").length,
    });
    if (latestCompleted) {
      const results = await this.prisma.assessmentRequirementResult.findMany({ where: { workspaceId, assessmentId: latestCompleted.id } });
      const tests = await this.prisma.controlTest.findMany({ where: { workspaceId } });
      coverage = coverageMetrics({
        requirementsTotal: results.length,
        requirementsAssessed: results.filter((r) => r.result !== "NOT_ASSESSED").length,
        controlsTotal: controls.length,
        controlsImplemented: controls.filter((c) => c.implementationStatus === "IMPLEMENTED").length,
        controlsTested: latestByControl.size,
        automatedControls: new Set(tests.filter((t) => t.method === "AUTOMATED").map((t) => t.controlId)).size,
        evidenceCurrent: evidence.length - staleEvidence, evidenceTotal: evidence.length,
        manualEvidencePending: evidence.filter((e) => e.reviewStatus === "PENDING").length,
      });
    }
    return {
      frameworks: frameworks.map((f) => ({ id: f.id, key: f.key, name: f.name, version: f.version, status: f.status })),
      assessments: assessments.slice(0, 10),
      overallAssessmentStatus: latestCompleted?.status ?? "NOT_STARTED",
      coverage,
      coverageLabel: "Assessment Coverage / Control Status — not a certification (§82)",
      technicalControlFailures: failedControls.length,
      failedControlIds: failedControls,
      staleEvidence,
      openExceptions: exceptions,
      upcomingReviews,
      disclaimer: GRC_DISCLAIMER,
    };
  }

  async frameworkDashboard(user: RequestUser, workspaceId: string, frameworkId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const framework = await this.prisma.complianceFramework.findFirst({ where: { id: frameworkId } });
    if (!framework) return { error: "Framework not found" };
    const requirements = await this.prisma.complianceRequirement.findMany({
      where: { frameworkId }, orderBy: [{ level: "asc" }, { requirementId: "asc" }],
    });
    const mappings = await this.prisma.controlFrameworkMapping.findMany({ where: { workspaceId } });
    const assessments = await this.prisma.complianceAssessment.findMany({
      where: { workspaceId, frameworkId }, orderBy: { createdAt: "desc" },
    });
    const latest = assessments[0];
    const results = latest
      ? await this.prisma.assessmentRequirementResult.findMany({ where: { workspaceId, assessmentId: latest.id } })
      : [];
    const resultByReq = new Map(results.map((r) => [r.requirementId, r.result]));
    return {
      framework,
      requirements: requirements.map((r) => ({
        ...r,
        mappedControlIds: mappings.filter((m) => m.requirementId === r.id).map((m) => m.controlId),
        latestResult: resultByReq.get(r.id) ?? "NOT_ASSESSED",
      })),
      assessmentHistory: assessments,
      disclaimer: GRC_DISCLAIMER,
    };
  }

  async riskDashboard(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_RISK_REGISTER");
    const risks = await this.prisma.riskRecord.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    const matrix: Record<string, number> = {};
    for (const r of risks) {
      const key = `${r.likelihood}x${Math.max(0, ...Object.values((r.impacts as Record<string, number>) ?? {}))}`;
      matrix[key] = (matrix[key] ?? 0) + 1;
    }
    const now = Date.now();
    const actions = await this.prisma.riskTreatmentAction.findMany({ where: { workspaceId } });
    const acceptances = await this.prisma.riskAcceptance.findMany({ where: { workspaceId, status: "ACCEPTED" } });
    return {
      risks,
      matrix,
      highResidualRisks: risks.filter((r) => r.residualBand === "HIGH" || r.residualBand === "CRITICAL"),
      overdueTreatments: actions.filter((a) => a.status !== "DONE" && a.dueDate && new Date(a.dueDate).getTime() < now),
      expiringAcceptances: acceptances.filter((a) => new Date(a.expiresAt).getTime() - now < 31 * 86_400_000 && new Date(a.expiresAt).getTime() > now),
      disclaimer: GRC_DISCLAIMER,
    };
  }

  async evidenceDashboard(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_COMPLIANCE_EVIDENCE");
    const rows = await this.prisma.complianceEvidence.findMany({
      where: { workspaceId }, orderBy: { collectedAt: "desc" }, take: 1000,
    });
    const now = new Date();
    const byStatus: Record<string, number> = {};
    const byClassification: Record<string, number> = {};
    for (const ev of rows) {
      const policy = await this.prisma.evidenceFreshnessPolicy.findFirst({ where: { workspaceId, controlId: ev.controlId } });
      const status = evidenceFreshness(new Date(ev.collectedAt).toISOString(), policy ?? { staleAfterDays: 335, expireAfterDays: 400 }, now, ev.status as never);
      byStatus[status] = (byStatus[status] ?? 0) + 1;
      byClassification[ev.classification] = (byClassification[ev.classification] ?? 0) + 1;
    }
    return { total: rows.length, byStatus, byClassification, items: rows.slice(0, 100) };
  }
}
