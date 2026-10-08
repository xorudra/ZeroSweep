import { createHash } from "node:crypto";
import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService, type CaseRow } from "./case-state.service";
import { VulnerabilityService } from "../vulnerabilities/vulnerability.service";
import { NotificationRouterService } from "../continuous-security/notifications/notification-router.service";

/**
 * Vulnerability regression engine (Prompt 31 §71–§77). A verified-fixed or
 * closed finding whose fingerprint reappears is a REGRESSION: the event
 * is recorded with before/after snapshots, the finding and its case
 * reopen, risk is recomputed from the CURRENT context (never inflated
 * at scanner level, §77), and the owner is notified through the P22
 * router. A DIFFERENT issue on the same asset does not match — identity
 * is the canonical fingerprint plus asset/component identity (§73).
 */
@Injectable()
export class RemediationRegressionService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly vulnerabilities: VulnerabilityService,
    private readonly notifications: NotificationRouterService,
  ) {}

  /**
   * Scan the workspace for regressions: canonical findings currently in
   * a resolved lifecycle state that have ACTIVE (non-duplicate)
   * observations — i.e. the scanner saw it again after the fix.
   */
  async detectRegressions(user: RequestUser, workspaceId: string, now = new Date()) {
    const canonicals = await this.prisma.finding.findMany({
      where: {
        workspaceId, duplicateOfId: null,
        lifecycleStatus: { in: ["RESOLVED"] },
      },
      take: 5000,
    });
    const detected: Array<{ caseId: string; findingId: string; fingerprint: string }> = [];
    for (const finding of canonicals) {
      if (!finding.fingerprint) continue; // identity unprovable (§73)
      const observations = await this.prisma.finding.findMany({
        where: { workspaceId, duplicateOfId: finding.id },
        take: 50,
      });
      const fresh = observations.filter((o) => o.lastSeen.getTime() > (finding.resolvedAt?.getTime() ?? 0));
      if (fresh.length === 0) continue;
      const result = await this.recordRegression(user, workspaceId, finding.id, fresh[0].id, now);
      if (result) detected.push({ caseId: result.case.id, findingId: finding.id, fingerprint: finding.fingerprint });
    }
    return { examined: canonicals.length, detected };
  }

  /** Record one regression for a canonical finding + reopen everything. */
  async recordRegression(user: RequestUser, workspaceId: string, findingId: string, observationId: string, now = new Date()) {
    const finding = await this.state.getFinding(workspaceId, findingId);
    let kase = (await this.prisma.remediationCase.findFirst({
      where: { workspaceId, findingId }, orderBy: { createdAt: "desc" },
    })) as CaseRow | null;
    if (!kase) return null;
    if (!["VERIFIED_FIXED", "CLOSED"].includes(kase.status)) return null;
    const observation = await this.state.getFinding(workspaceId, observationId);
    // Identity check (§73): fingerprint must match the canonical one —
    // a different bug on the same asset is a new finding, not a
    // regression. No fingerprint on either side = identity unprovable.
    if (!finding.fingerprint || !observation.fingerprint) return null;
    const sameIdentity = createHash("sha256").update(observation.fingerprint).digest("hex")
      === createHash("sha256").update(finding.fingerprint).digest("hex");
    if (!sameIdentity) return null;
    const previousVerifiedAt = kase.verifiedFixedAt;
    kase = await this.state.transition(user, workspaceId, kase, {
      to: "REOPENED", reason: "vulnerability regression detected — the fixed issue reappeared (§72)",
      evidence: {
        observationId, observedAt: observation.lastSeen,
        before: { status: kase.status, verifiedFixedAt: kase.verifiedFixedAt, closedAt: kase.closedAt, findingLifecycle: finding.lifecycleStatus },
        after: { host: observation.host, componentPurl: observation.componentPurl, assetId: observation.assetId },
      },
      event: "VULNERABILITY_REGRESSION_DETECTED",
      extraData: { regressionCount: kase.regressionCount + 1, lastRegressionAt: now, verificationState: "NOT_REQUESTED" },
    });
    const event = await this.prisma.remediationRegressionEvent.create({
      data: {
        caseId: kase.id, workspaceId, findingId,
        fingerprint: finding.fingerprint, detectedAt: now,
        previousVerifiedAt, source: "SCAN_OBSERVATION",
      },
    });
    // The finding reopens through the lifecycle machine (§72 — in the
    // P11 machine a recurrence moves RESOLVED → NEW) and its risk is
    // recalculated from current context (§77) — the regression count may
    // raise CONTEXTUAL risk, never scanner severity.
    try {
      await this.vulnerabilities.transition(user, workspaceId, findingId, {
        to: "NEW" as never, reason: "regression detected — fixed issue reappeared (Prompt 31 §72)",
      });
    } catch { /* resting state governs; the case already reopened */ }
    const risk = await this.vulnerabilities.applyEnrichment(user, workspaceId, findingId)
      .then((r) => r.risk)
      .catch(() => null);
    if (risk) {
      await this.prisma.remediationRegressionEvent.update({
        where: { id: event.id }, data: { riskRecalculation: risk as never },
      });
    }
    await this.notifications.routeEvent(workspaceId, {
      type: "VULNERABILITY_REGRESSION_DETECTED", workspaceId, findingId,
      severity: finding.severity, priority: kase.priority ?? finding.priority ?? undefined,
      contentHash: `regression:${finding.id}:${event.id}`,
      title: `Vulnerability regression: ${finding.title}`,
      detail: `previously verified fixed; observed again (${observationId})`,
    }, now);
    return { case: kase, event, risk };
  }

  async listRegressions(workspaceId: string, caseId?: string) {
    return this.prisma.remediationRegressionEvent.findMany({
      where: { workspaceId, ...(caseId ? { caseId } : {}) },
      orderBy: { detectedAt: "desc" }, take: 500,
    });
  }
}
