import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { createHash } from "node:crypto";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { RemediationCasesService } from "./cases.service";
import { RemediationAnalyticsService } from "./analytics.service";
import { RemediationSlaService } from "./sla.service";
import { requireRemediationPermission } from "./permissions";

/** The §128 remediation report types (distinct from the P20 unified
 *  report catalogue — remediation reports snapshot remediation state). */
export const REMEDIATION_REPORT_TYPES = [
  "REMEDIATION_STATUS", "SLA_COMPLIANCE", "OVERDUE_REMEDIATION",
  "KEV_REMEDIATION", "REGRESSION_REPORT", "CAMPAIGN_REPORT",
  "EXECUTIVE_REMEDIATION",
] as const;

/**
 * Remediation reports (Prompt 31 §128/§129). A report is an immutable,
 * content-hashed SNAPSHOT of the remediation state at generation time
 * — later state changes never rewrite a delivered report.
 */
@Injectable()
export class RemediationReportsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly cases: RemediationCasesService,
    private readonly analytics: RemediationAnalyticsService,
    private readonly sla: RemediationSlaService,
  ) {}

  async generate(user: RequestUser, workspaceId: string, input: { type: string; campaignId?: string }, now = new Date()) {
    requireRemediationPermission(user, "VIEW_REMEDIATION");
    if (!(REMEDIATION_REPORT_TYPES as readonly string[]).includes(input.type)) {
      throw new BadRequestException(`report type must be one of ${REMEDIATION_REPORT_TYPES.join(", ")} (§128)`);
    }
    const queue = await this.cases.listQueue(workspaceId, { pageSize: 200 });
    const metrics = await this.analytics.metrics(workspaceId, {}, now);
    const sla = await this.sla.dashboard(workspaceId, now);
    const regressions = await this.prisma.remediationRegressionEvent.findMany({
      where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 200,
    });
    const content: Record<string, unknown> = {
      type: input.type, generatedAt: now.toISOString(), generatedBy: user.id,
      dashboard: await this.cases.dashboard(workspaceId, now),
      metrics, sla,
    };
    if (input.type === "OVERDUE_REMEDIATION") {
      content.overdue = queue.items.filter((i) => i.dueAt != null && i.dueAt.getTime() < now.getTime());
    }
    if (input.type === "KEV_REMEDIATION") {
      const kev = await this.cases.listQueue(workspaceId, { kev: true, pageSize: 200 });
      content.kevCases = kev.items;
    }
    if (input.type === "REGRESSION_REPORT") content.regressions = regressions;
    if (input.type === "CAMPAIGN_REPORT") {
      if (!input.campaignId) throw new BadRequestException("CAMPAIGN_REPORT requires campaignId");
      content.campaignId = input.campaignId;
    }
    const snapshot = await this.prisma.remediationReportSnapshot.create({
      data: {
        workspaceId, type: input.type, generatedBy: user.id,
        contentHash: createHash("sha256").update(JSON.stringify(content)).digest("hex"),
        content: content as never,
      },
    });
    return snapshot;
  }

  async list(workspaceId: string) {
    return this.prisma.remediationReportSnapshot.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100,
      select: { id: true, type: true, contentHash: true, generatedBy: true, createdAt: true },
    });
  }

  async get(workspaceId: string, id: string) {
    const row = await this.prisma.remediationReportSnapshot.findFirst({ where: { id, workspaceId } });
    if (!row) throw new BadRequestException("report snapshot not found in this workspace");
    return row;
  }
}
