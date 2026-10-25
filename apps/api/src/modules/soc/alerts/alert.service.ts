import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  computeAlertPriority, type AlertPriority, type DetectionConfidence,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { OPEN_ALERT_STATUSES, type Row } from "../helpers";

export interface RaiseAlertInput {
  organizationId: string;
  workspaceId: string;
  fingerprint: string;
  title: string;
  description?: string;
  severity: string;
  source: string; // DETECTION | CORRELATION | INDICATOR_MATCH | MANUAL
  ruleId?: string;
  assetId?: string;
  identityReference?: string;
  indicatorId?: string;
  findingId?: string;
  confidence?: DetectionConfidence;
  assetCriticality?: string;
  internetExposed?: boolean;
  identityPrivileged?: boolean;
  kev?: boolean;
  threatIntelConfidence?: number;
  correlationSignalCount?: number;
  actorId?: string;
}

/**
 * Alert engine (Prompt 28 §30–§40). One place raises alerts so
 * dedupe (§32), suppression (§39) and prioritization (§34) are
 * uniform across detections, correlations and indicator matches.
 * Alerts derive ONLY from real platform records — every raise call
 * carries the record references that justify it.
 */
@Injectable()
export class AlertService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /** §39: a suppression applies when every non-null scope field on
   *  the suppression matches the candidate alert, and it has not
   *  expired (§137). Suppressions can never be permanent: expiresAt
   *  is a required column (§40). */
  async findApplicableSuppression(workspaceId: string, input: { ruleId?: string; assetId?: string; identityReference?: string }): Promise<Row | null> {
    const rules = await this.prisma.alertSuppressionRule.findMany({
      where: { workspaceId, expiresAt: { gt: new Date() } },
    });
    for (const rule of rules as Row[]) {
      if (rule.ruleId && rule.ruleId !== input.ruleId) continue;
      if (rule.assetId && rule.assetId !== input.assetId) continue;
      if (rule.identityReference && rule.identityReference !== input.identityReference) continue;
      if (!rule.ruleId && !rule.assetId && !rule.identityReference) continue; // unscoped rows never apply
      return rule;
    }
    return null;
  }

  async raiseAlert(input: RaiseAlertInput): Promise<{ alert: Row | null; created: boolean; suppressed: boolean }> {
    const suppression = await this.findApplicableSuppression(input.workspaceId, input);
    if (suppression) {
      await this.audit.record({
        actorId: input.actorId, organizationId: input.organizationId, workspaceId: input.workspaceId,
        action: "ALERT_SUPPRESSED", resourceType: "SecurityAlert",
        metadata: { suppressionId: suppression.id as string, ruleId: input.ruleId, fingerprint: input.fingerprint },
      }).catch(() => undefined);
      return { alert: null, created: false, suppressed: true };
    }
    const existing = await this.prisma.securityAlert.findFirst({
      where: { workspaceId: input.workspaceId, fingerprint: input.fingerprint, status: { in: OPEN_ALERT_STATUSES } },
    });
    if (existing) {
      const updated = await this.prisma.securityAlert.update({
        where: { id: existing.id as string },
        data: { occurrenceCount: ((existing.occurrenceCount as number | undefined) ?? 1) + 1, lastSeen: new Date() },
      });
      return { alert: updated as Row, created: false, suppressed: false };
    }
    const priority = computeAlertPriority({
      severity: input.severity, confidence: input.confidence ?? "MEDIUM",
      assetCriticality: input.assetCriticality, internetExposed: input.internetExposed,
      identityPrivileged: input.identityPrivileged, kev: input.kev,
      threatIntelConfidence: input.threatIntelConfidence, correlationSignalCount: input.correlationSignalCount,
    });
    const alert = await this.prisma.securityAlert.create({
      data: {
        organizationId: input.organizationId, workspaceId: input.workspaceId,
        fingerprint: input.fingerprint, title: input.title, description: input.description ?? "",
        severity: input.severity, priority: priority.priority as AlertPriority, priorityScore: priority.score,
        priorityFactors: priority.factors as never, status: "NEW", source: input.source, occurrenceCount: 1,
        ruleId: input.ruleId, assetId: input.assetId, identityReference: input.identityReference,
        indicatorId: input.indicatorId, findingId: input.findingId,
      },
    });
    await this.audit.record({
      actorId: input.actorId, organizationId: input.organizationId, workspaceId: input.workspaceId,
      action: "ALERT_CREATED", resourceType: "SecurityAlert", resourceId: alert.id as string,
      metadata: { priority: priority.priority, severity: input.severity, source: input.source, ruleId: input.ruleId },
    }).catch(() => undefined);
    return { alert: alert as Row, created: true, suppressed: false };
  }

  async listAlerts(user: RequestUser, workspaceId: string, filters: {
    status?: string; priority?: string; severity?: string; ruleId?: string; assetId?: string;
    identityReference?: string; indicatorId?: string; limit?: number;
  }) {
    requireSocPermission(user, "VIEW_SOC");
    const items = await this.prisma.securityAlert.findMany({
      where: {
        workspaceId,
        ...(filters.status ? { status: filters.status } : {}),
        ...(filters.priority ? { priority: filters.priority } : {}),
        ...(filters.severity ? { severity: filters.severity } : {}),
        ...(filters.ruleId ? { ruleId: filters.ruleId } : {}),
        ...(filters.assetId ? { assetId: filters.assetId } : {}),
        ...(filters.identityReference ? { identityReference: filters.identityReference } : {}),
        ...(filters.indicatorId ? { indicatorId: filters.indicatorId } : {}),
      },
      orderBy: { firstSeen: "desc" },
      take: Math.min(filters.limit ?? 100, 500),
    });
    return { items, total: items.length };
  }

  /** Tenant-scoped fetch: another tenant's alert is a 404 (§154). */
  async getAlert(user: RequestUser, workspaceId: string, alertId: string): Promise<Row> {
    requireSocPermission(user, "VIEW_SOC");
    const alert = await this.prisma.securityAlert.findFirst({ where: { id: alertId, workspaceId } });
    if (!alert) throw new NotFoundException("Alert not found in this workspace");
    return alert as Row;
  }

  async getAlertDetail(user: RequestUser, workspaceId: string, alertId: string) {
    const alert = await this.getAlert(user, workspaceId, alertId);
    const [matches, triage, rule] = await Promise.all([
      this.prisma.detectionMatch.findMany({ where: { workspaceId, alertId }, orderBy: { matchedAt: "desc" }, take: 50 }),
      this.prisma.alertTriage.findMany({ where: { workspaceId, alertId }, orderBy: { createdAt: "desc" }, take: 50 }),
      alert.ruleId ? this.prisma.detectionRule.findFirst({ where: { id: alert.ruleId as string, workspaceId } }) : Promise.resolve(null),
    ]);
    const asset = alert.assetId
      ? await this.prisma.asset.findFirst({ where: { id: alert.assetId as string } }).catch(() => null)
      : null;
    const finding = alert.findingId
      ? await this.prisma.finding.findFirst({ where: { id: alert.findingId as string, workspaceId } }).catch(() => null)
      : null;
    const indicator = alert.indicatorId
      ? await this.prisma.threatIndicator.findFirst({ where: { id: alert.indicatorId as string, workspaceId } }).catch(() => null)
      : null;
    return { alert, detectionMatches: matches, triage, rule, asset, finding, indicator };
  }

  async patchAlert(user: RequestUser, workspaceId: string, alertId: string, body: { status?: string; ownerId?: string }) {
    const alert = await this.getAlert(user, workspaceId, alertId);
    const data: Row = {};
    if (body.ownerId !== undefined) {
      requireSocPermission(user, "ASSIGN_ALERTS");
      data.ownerId = body.ownerId;
    }
    if (body.status !== undefined) {
      requireSocPermission(user, "TRIAGE_ALERTS");
      data.status = body.status;
      if (body.status === "CONTAINED" && !alert.containedAt) data.containedAt = new Date();
      if ((body.status === "RESOLVED" || body.status === "CLOSED") && !alert.resolvedAt) data.resolvedAt = new Date();
    }
    const updated = await this.prisma.securityAlert.update({ where: { id: alertId }, data: data as never });
    return updated;
  }

  /** §36/§37: record a triage decision. FALSE_POSITIVE feeds the
   *  false-positive trend (§38) — it never auto-disables the rule. */
  async triageAlert(user: RequestUser, workspaceId: string, alertId: string, body: { decision: string; reason?: string; notes?: string }) {
    requireSocPermission(user, "TRIAGE_ALERTS");
    const alert = await this.getAlert(user, workspaceId, alertId);
    const triage = await this.prisma.alertTriage.create({
      data: {
        alertId, workspaceId, analystId: user.id, decision: body.decision,
        reason: body.reason ?? "", notes: body.notes ?? "",
      },
    });
    const data: Row = { acknowledgedAt: alert.acknowledgedAt ?? new Date() };
    if (alert.status === "NEW") data.status = "TRIAGED";
    if (body.decision === "DUPLICATE") data.status = "CLOSED";
    await this.prisma.securityAlert.update({ where: { id: alertId }, data: data as never });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "ALERT_TRIAGED", resourceType: "SecurityAlert", resourceId: alertId,
      metadata: { decision: body.decision },
    });
    return triage;
  }

  async createSuppression(user: RequestUser, workspaceId: string, body: {
    ruleId?: string; assetId?: string; identityReference?: string; reason: string; expiresAt: string; approvedBy?: string;
  }) {
    requireSocPermission(user, "TRIAGE_ALERTS");
    if (!body.ruleId && !body.assetId && !body.identityReference) {
      throw new BadRequestException("A suppression must be scoped to a rule, an asset, or an identity (§39) — broad suppression does not exist (§40)");
    }
    const expiresAt = new Date(body.expiresAt);
    if (Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
      throw new BadRequestException("Suppression expiresAt must be in the future (§39/§137)");
    }
    const maxWindow = 90 * 24 * 3600 * 1000;
    if (expiresAt.getTime() - Date.now() > maxWindow) {
      throw new BadRequestException("Suppression window exceeds the 90-day maximum — permanent suppression requires explicit re-approval (§40)");
    }
    const suppression = await this.prisma.alertSuppressionRule.create({
      data: {
        organizationId: user.organizationId, workspaceId, ruleId: body.ruleId, assetId: body.assetId,
        identityReference: body.identityReference, reason: body.reason, createdBy: user.id,
        approvedBy: body.approvedBy, expiresAt,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "ALERT_SUPPRESSED", resourceType: "AlertSuppressionRule", resourceId: suppression.id as string,
      metadata: { ruleId: body.ruleId, expiresAt: body.expiresAt },
    });
    return suppression;
  }

  async listSuppressions(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const items = await this.prisma.alertSuppressionRule.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    return { items, total: items.length };
  }
}
