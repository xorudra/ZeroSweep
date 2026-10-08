import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { GRC_DISCLAIMER, hashEvidence } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import { redactForPackage } from "../grc-helpers";
import { GrcAnalyticsService } from "../analytics/analytics.service";
import type { CreateReportInput } from "../dto/schemas";

/**
 * GRC reporting (Prompt 26 §114–§117). Issued reports are immutable
 * snapshots (§115): content is computed once, redacted through the
 * platform discipline, hashed, and stored — later state changes never
 * alter an issued report. Exports render from the snapshot only.
 * Restricted-evidence snapshots are never embedded in reports (§143).
 */
@Injectable()
export class GrcReportService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly analytics: GrcAnalyticsService,
  ) {}

  private async buildContent(user: RequestUser, workspaceId: string, input: CreateReportInput) {
    const base = { generatedAt: new Date().toISOString(), disclaimer: GRC_DISCLAIMER };
    switch (input.reportType) {
      case "EXECUTIVE_GRC": {
        const dash = await this.analytics.complianceDashboard(user, workspaceId);
        const riskDash = await this.analytics.riskDashboard(user, workspaceId);
        return {
          ...base, kind: "EXECUTIVE_GRC",
          assessmentStatus: dash.overallAssessmentStatus, coverage: dash.coverage,
          technicalControlFailures: dash.technicalControlFailures, staleEvidence: dash.staleEvidence,
          openExceptions: dash.openExceptions, upcomingReviews: dash.upcomingReviews,
          highResidualRisks: riskDash.highResidualRisks.map((r) => ({ id: r.id, title: r.title, residualBand: r.residualBand })),
          overdueTreatments: riskDash.overdueTreatments.length,
        };
      }
      case "COMPLIANCE_ASSESSMENT": {
        if (!input.assessmentId) throw new BadRequestException("COMPLIANCE_ASSESSMENT reports require assessmentId");
        const assessment = await this.prisma.complianceAssessment.findFirst({ where: { id: input.assessmentId, workspaceId } });
        if (!assessment) throw new NotFoundException("Assessment not found in this workspace");
        const results = await this.prisma.assessmentRequirementResult.findMany({
          where: { workspaceId, assessmentId: input.assessmentId },
        });
        return {
          ...base, kind: "COMPLIANCE_ASSESSMENT",
          framework: { key: assessment.frameworkKey, version: assessment.frameworkVersion },
          assessment: { id: assessment.id, name: assessment.name, status: assessment.status },
          results: results.map((r) => ({
            requirementId: r.requirementId, result: r.result, reviewStatus: r.reviewStatus,
            controlCount: (r.controlIds as string[]).length, evidenceCount: (r.evidenceIds as string[]).length,
          })),
        };
      }
      case "CONTROL_EFFECTIVENESS": {
        const controls = await this.prisma.securityControl.findMany({ where: { workspaceId }, orderBy: { code: "asc" } });
        return {
          ...base, kind: "CONTROL_EFFECTIVENESS",
          controls: controls.map((c) => ({
            code: c.code, title: c.title, implementationStatus: c.implementationStatus, effectiveness: c.effectiveness,
          })),
        };
      }
      case "RISK_REGISTER":
      case "RISK_TREATMENT": {
        const risks = await this.prisma.riskRecord.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
        const plans = await this.prisma.riskTreatmentPlan.findMany({ where: { workspaceId } });
        return {
          ...base, kind: input.reportType,
          risks: risks.map((r) => ({
            id: r.id, title: r.title, source: r.source, inherent: `${r.inherentScore} (${r.inherentBand})`,
            residual: r.residualScore === null ? "NOT_ASSESSED (§49)" : `${r.residualScore} (${r.residualBand})`,
            status: r.status, treatment: r.treatment,
          })),
          treatmentPlans: plans.map((p) => ({ riskId: p.riskId, strategy: p.strategy, status: p.status })),
        };
      }
      case "AUDIT_READINESS": {
        const audits = await this.prisma.auditEngagement.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
        const requests = await this.prisma.auditEvidenceRequest.findMany({ where: { workspaceId } });
        return {
          ...base, kind: "AUDIT_READINESS",
          audits: audits.map((a) => ({ id: a.id, type: a.type, status: a.status })),
          openRequests: requests.filter((r) => ["OPEN", "IN_PROGRESS", "OVERDUE"].includes(r.status)).length,
          submittedRequests: requests.filter((r) => r.status === "SUBMITTED").length,
        };
      }
      case "EVIDENCE_FRESHNESS": {
        const dash = await this.analytics.evidenceDashboard(user, workspaceId);
        return { ...base, kind: "EVIDENCE_FRESHNESS", total: dash.total, byStatus: dash.byStatus, byClassification: dash.byClassification };
      }
      default:
        throw new BadRequestException(`Unknown report type ${input.reportType}`);
    }
  }

  async generateReport(user: RequestUser, workspaceId: string, input: CreateReportInput) {
    requireGrcPermission(user, "VIEW_GRC");
    const content = await this.buildContent(user, workspaceId, input);
    // Redaction pass over the serialized content (§117 sanitized exports).
    const redacted = JSON.parse(redactForPackage(JSON.stringify(content))) as Record<string, unknown>;
    const row = await this.prisma.grcReportSnapshot.create({
      data: {
        workspaceId, reportType: input.reportType,
        title: `${input.reportType} report — ${new Date().toISOString().slice(0, 10)}`,
        content: redacted as never, contentHash: hashEvidence(redacted), generatedBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "REPORT_GENERATED", resourceType: "GrcReportSnapshot", resourceId: row.id,
      metadata: { reportType: input.reportType, contentHash: row.contentHash },
    });
    return row;
  }

  async listReports(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const items = await this.prisma.grcReportSnapshot.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100,
    });
    return { items, total: items.length };
  }

  /** §117: sanitized export of an issued snapshot — JSON or CSV. PDF
   *  rendering reuses the platform report pipeline; the GRC snapshot
   *  is the source of truth either way. */
  async exportReport(user: RequestUser, workspaceId: string, id: string, format: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const row = await this.prisma.grcReportSnapshot.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Report snapshot not found in this workspace");
    if (format === "json") {
      return { format: "json", filename: `${row.reportType.toLowerCase()}-report.json`, content: row.content, contentHash: row.contentHash };
    }
    if (format === "csv") {
      const content = row.content as Record<string, unknown>;
      const rows: string[] = ["section,key,value"];
      const walk = (section: string, value: unknown) => {
        if (Array.isArray(value)) value.forEach((v, i) => walk(`${section}[${i}]`, v));
        else if (value && typeof value === "object") for (const [k, v] of Object.entries(value)) walk(`${section}.${k}`, v);
        else rows.push(`${csv(section)},${csv("")},${csv(String(value ?? ""))}`);
      };
      walk(row.reportType, content);
      return { format: "csv", filename: `${row.reportType.toLowerCase()}-report.csv`, content: rows.join("\n"), contentHash: row.contentHash };
    }
    throw new BadRequestException(`Unsupported GRC export format ${format} (json | csv)`);
  }
}

function csv(value: string): string {
  // CSV formula-injection guard (platform discipline from Prompt 20).
  const guarded = /^[=+\-@]/.test(value) ? `'${value}` : value;
  return `"${guarded.replace(/"/g, '""')}"`;
}
