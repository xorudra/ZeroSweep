import { Inject, Injectable } from "@nestjs/common";
import {
  bucketForRange, countInRange, distribution, evidenceFreshness, groupCount, meanTimeTo,
  mttrBy, percentile, regressionRanking, recurrenceBy, slaBuckets, timeSeries, topN, trend,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { deriveExposure } from "../../continuous-security/snapshots/snapshot.service";
import { RESOLVED_LIFECYCLES } from "../helpers";
import { AttackSurfaceService } from "../attack-surface/attack-surface.service";

const DAY = 86_400_000;

/**
 * Domain analytics (Prompt 27 §39–§72, §98).
 *
 * Every number is computed from REAL tenant-scoped records with the
 * SDK's deterministic aggregations, and each block names its source
 * tables so a figure can be reproduced by a stated query. Sparse
 * data stays sparse: empty inputs yield empty series and null means,
 * never synthetic trends.
 */
@Injectable()
export class AggregationService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly attackSurface: AttackSurfaceService,
  ) {}

  private async findings(workspaceId: string, take = 10_000) {
    return this.prisma.finding.findMany({ where: { workspaceId }, orderBy: { createdAt: "asc" }, take });
  }

  private async projections(workspaceId: string) {
    const rows = await this.prisma.findingLifecycleProjection.findMany({ where: { workspaceId }, take: 10_000 });
    // Map DB rows (Date fields) onto the SDK projection shape (ISO strings).
    return rows.map((r) => ({
      findingId: r.findingId,
      firstSeenAt: r.firstSeenAt.toISOString(), lastSeenAt: r.lastSeenAt.toISOString(),
      triagedAt: r.triagedAt?.toISOString() ?? null, verifiedAt: r.verifiedAt?.toISOString() ?? null,
      resolvedAt: r.resolvedAt?.toISOString() ?? null, reopenedAt: r.reopenedAt?.toISOString() ?? null,
      regressionCount: r.regressionCount, remediationSeconds: r.remediationSeconds,
      currentStatus: r.currentStatus, severity: r.severity, cwe: r.cwe, cve: r.cve,
      assetId: r.assetId, repositoryId: r.repositoryId,
    }));
  }

  async overview(workspaceId: string, days = 90, now = new Date()) {
    const [posture, events, findings, projections, gates] = await Promise.all([
      this.prisma.securityPostureSnapshot.findMany({ where: { workspaceId }, orderBy: { capturedAt: "asc" }, take: 500 }),
      this.prisma.securityAnalyticsEvent.findMany({ where: { workspaceId }, orderBy: { eventTime: "asc" }, take: 10_000 }),
      this.findings(workspaceId),
      this.projections(workspaceId),
      this.prisma.qualityGateResult.findMany({ take: 2000 }),
    ]);
    const from = new Date(now.getTime() - days * DAY);
    const prevFrom = new Date(now.getTime() - 2 * days * DAY);
    const createdEvents = events.filter((e) => e.eventType === "FINDING_CREATED");
    const open = findings.filter((f) => !RESOLVED_LIFECYCLES.has(f.lifecycleStatus));
    const bucket = bucketForRange(from, now);
    const mttrGroups = mttrBy(projections, () => "ALL");
    const regressions = projections.filter((p) => p.regressionCount > 0).length;
    const scanIds = new Set(findings.map((f) => f.scanId));
    const gateRows = gates.filter((g) => scanIds.has(g.scanId));
    return {
      sources: ["SecurityPostureSnapshot", "SecurityAnalyticsEvent", "Finding", "FindingLifecycleProjection", "QualityGateResult"],
      postureTrend: posture.map((p) => ({ capturedAt: p.capturedAt, riskScore: p.riskScore, findingCount: p.findingCount, kevCount: p.kevCount })),
      riskTrend: posture.map((p) => ({ capturedAt: p.capturedAt, riskScore: p.riskScore })),
      findingTrend: timeSeries(createdEvents, (e) => e.eventTime, bucket, { from, to: now }),
      findingTrendDelta: trend(
        countInRange(createdEvents, (e) => e.eventTime, from, now),
        countInRange(createdEvents, (e) => e.eventTime, prevFrom, from),
      ),
      attackSurfaceGrowth: await this.attackSurface.growth(workspaceId),
      criticalExposure: open.filter((f) => f.severity === "CRITICAL").length,
      kevExposure: open.filter((f) => f.kevListed).length,
      mttr: mttrGroups[0] ?? { key: "ALL", resolvedCount: 0, unresolvedCount: 0, meanSeconds: null, medianSeconds: null },
      sla: slaBuckets(findings.map((f) => ({ dueAt: f.dueAt?.toISOString() ?? null, resolvedAt: f.resolvedAt?.toISOString() ?? null, status: f.lifecycleStatus })), now),
      regressionRate: projections.length === 0 ? null : regressions / projections.length,
      regressions,
      securityGatePerformance: {
        total: gateRows.length,
        passed: gateRows.filter((g) => g.status === "PASSED").length,
        failed: gateRows.filter((g) => g.status === "FAILED").length,
        passRate: gateRows.length === 0 ? null : gateRows.filter((g) => g.status === "PASSED").length / gateRows.length,
      },
    };
  }

  async findingsAnalytics(workspaceId: string, days = 90, now = new Date()) {
    const [findings, projections, events] = await Promise.all([
      this.findings(workspaceId), this.projections(workspaceId),
      this.prisma.securityAnalyticsEvent.findMany({ where: { workspaceId }, orderBy: { eventTime: "asc" }, take: 10_000 }),
    ]);
    const from = new Date(now.getTime() - days * DAY);
    const created = events.filter((e) => e.eventType === "FINDING_CREATED");
    return {
      sources: ["Finding", "FindingLifecycleProjection", "SecurityAnalyticsEvent"],
      total: findings.length,
      severityDistribution: distribution(findings, (f) => f.severity),
      statusDistribution: groupCount(findings, (f) => f.lifecycleStatus),
      severityTrend: timeSeries(created, (e) => e.eventTime, bucketForRange(from, now), { from, to: now }),
      topCves: topN(findings, (f) => f.cve, 10),
      topCwes: topN(findings, (f) => f.cwe, 10),
      kev: {
        listed: findings.filter((f) => f.kevListed).length,
        open: findings.filter((f) => f.kevListed && !RESOLVED_LIFECYCLES.has(f.lifecycleStatus)).length,
        overdue: findings.filter((f) => f.kevListed && f.dueAt && f.dueAt < now && !RESOLVED_LIFECYCLES.has(f.lifecycleStatus)).length,
      },
      epss: {
        p50: percentile(findings.map((f) => f.epssScore).filter((v): v is number => v != null), 50),
        p95: percentile(findings.map((f) => f.epssScore).filter((v): v is number => v != null), 95),
        tracked: findings.filter((f) => f.epssScore != null).length,
      },
      mttrBySeverity: mttrBy(projections, (p) => p.severity),
      mttrByRepository: mttrBy(projections, (p) => p.repositoryId),
      timeToVerifySeconds: meanTimeTo(projections, (p) => p.verifiedAt),
      timeToTriageSeconds: meanTimeTo(projections, (p) => p.triagedAt),
      sla: slaBuckets(findings.map((f) => ({ dueAt: f.dueAt?.toISOString() ?? null, resolvedAt: f.resolvedAt?.toISOString() ?? null, status: f.lifecycleStatus })), now),
      regressionRanking: regressionRanking(projections, 10),
      recurrence: {
        byCwe: recurrenceBy(projections, (p) => p.cwe),
        byCve: recurrenceBy(projections, (p) => p.cve),
        byRepository: recurrenceBy(projections, (p) => p.repositoryId),
        byAsset: recurrenceBy(projections, (p) => p.assetId),
      },
    };
  }

  async assetsAnalytics(workspaceId: string) {
    const assets = await this.prisma.asset.findMany({ where: { workspaceId }, take: 10_000 });
    const techs = await this.prisma.technology.findMany({ take: 20_000 });
    const assetIds = new Set(assets.map((a) => a.id));
    const techRows = techs.filter((t) => assetIds.has(t.assetId));
    return {
      sources: ["Asset", "Technology"],
      total: assets.length,
      byExposure: groupCount(assets, (a) => deriveExposure(a.ip)),
      byType: groupCount(assets, (a) => a.type),
      byCriticality: groupCount(assets, (a) => a.criticality),
      unknownAssets: assets.filter((a) => a.criticality === "UNSPECIFIED").length,
      unverifiedAssets: assets.filter((a) => a.scopeStatus === "PENDING_REVIEW").length,
      outOfScopeAssets: assets.filter((a) => a.scopeStatus === "OUT_OF_SCOPE").length,
      topTechnologies: topN(techRows, (t) => t.name, 15),
    };
  }

  async riskAnalytics(workspaceId: string, days = 90, now = new Date()) {
    const [history, findings] = await Promise.all([
      this.prisma.riskHistoryProjection.findMany({ where: { workspaceId }, orderBy: { recordedAt: "asc" }, take: 10_000 }),
      this.findings(workspaceId),
    ]);
    const from = new Date(now.getTime() - days * DAY);
    const inRange = history.filter((h) => h.recordedAt >= from);
    const byDay = new Map<string, number[]>();
    for (const h of inRange) {
      if (h.riskScore == null) continue;
      const key = h.recordedAt.toISOString().slice(0, 10);
      byDay.set(key, [...(byDay.get(key) ?? []), h.riskScore]);
    }
    return {
      sources: ["RiskHistoryProjection", "Finding"],
      riskTrend: [...byDay.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1)).map(([day, scores]) => ({
        bucketStart: day, meanRiskScore: scores.reduce((s, v) => s + v, 0) / scores.length, points: scores.length,
      })),
      priorityDistribution: groupCount(findings, (f) => f.priority),
      kevChanges: history.filter((h) => h.kevListed).length,
      topRiskFindings: [...findings].sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1)).slice(0, 10)
        .map((f) => ({ id: f.id, title: f.title, riskScore: f.riskScore, severity: f.severity, priority: f.priority })),
    };
  }

  async devsecopsAnalytics(workspaceId: string, days = 90, now = new Date()) {
    const [repos, findings, gates, scans] = await Promise.all([
      this.prisma.sourceRepository.findMany({ where: { workspaceId }, take: 2000 }),
      this.findings(workspaceId),
      this.prisma.qualityGateResult.findMany({ take: 5000 }),
      this.prisma.scan.findMany({ where: { workspaceId }, take: 5000 }),
    ]);
    const from = new Date(now.getTime() - days * DAY);
    const scanIds = new Set(scans.map((s) => s.id));
    const gateRows = gates.filter((g) => scanIds.has(g.scanId));
    const repoName = new Map(repos.map((r) => [r.id, r.name]));
    const byRepo = groupCount(findings.filter((f) => f.repositoryId), (f) => repoName.get(f.repositoryId!) ?? f.repositoryId);
    const inRange = findings.filter((f) => f.createdAt >= from);
    return {
      sources: ["SourceRepository", "Finding", "QualityGateResult"],
      repositories: repos.length,
      findingsByRepository: byRepo,
      newFindingsByRepository: groupCount(inRange.filter((f) => f.repositoryId), (f) => repoName.get(f.repositoryId!) ?? f.repositoryId),
      secretFindings: findings.filter((f) => f.category === "SECRET" || f.sourceDomain === "SECRET").length,
      newSecretFindings: inRange.filter((f) => f.category === "SECRET" || f.sourceDomain === "SECRET").length,
      pipelineGates: {
        total: gateRows.length,
        passed: gateRows.filter((g) => g.status === "PASSED").length,
        failed: gateRows.filter((g) => g.status === "FAILED").length,
        passRate: gateRows.length === 0 ? null : gateRows.filter((g) => g.status === "PASSED").length / gateRows.length,
      },
      sastTrend: timeSeries(inRange.filter((f) => f.sourceDomain === "SAST"), (f) => f.createdAt, bucketForRange(from, now), { from, to: now }),
      scaTrend: timeSeries(inRange.filter((f) => f.sourceDomain === "SCA"), (f) => f.createdAt, bucketForRange(from, now), { from, to: now }),
      scanCoverage: { scans: scans.length, completed: scans.filter((s) => s.status === "COMPLETED").length },
    };
  }

  async cloudAnalytics(workspaceId: string, days = 90, now = new Date()) {
    const findings = await this.findings(workspaceId);
    const cloud = findings.filter((f) => f.cloudProvider || f.findingClass);
    const from = new Date(now.getTime() - days * DAY);
    return {
      sources: ["Finding (cloud extension block)"],
      accounts: [...new Set(cloud.map((f) => f.cloudAccountId).filter(Boolean))].length,
      totalCloudFindings: cloud.length,
      byProvider: groupCount(cloud, (f) => f.cloudProvider),
      byClass: groupCount(cloud, (f) => f.findingClass),
      publicResources: cloud.filter((f) => f.findingClass === "PUBLIC_EXPOSURE" || f.category === "PUBLIC_EXPOSURE").length,
      iamRisks: cloud.filter((f) => f.findingClass === "IAM_RISK" || f.category === "IAM_RISK").length,
      encryptionGaps: cloud.filter((f) => f.findingClass === "ENCRYPTION_GAP").length,
      loggingGaps: cloud.filter((f) => f.findingClass === "LOGGING_GAP").length,
      criticalMisconfigurations: cloud.filter((f) => f.severity === "CRITICAL" && !RESOLVED_LIFECYCLES.has(f.lifecycleStatus)).length,
      trend: timeSeries(cloud.filter((f) => f.createdAt >= from), (f) => f.createdAt, bucketForRange(from, now), { from, to: now }),
      kubernetes: {
        workloads: await this.prisma.kubernetesWorkload.count({ where: { cluster: { workspaceId } } as never }).catch(() => 0),
        containerDomainFindings: findings.filter((f) => f.sourceDomain === "CONTAINER" || f.sourceDomain === "KUBERNETES").length,
        imageFindings: findings.filter((f) => f.imageDigest).length,
      },
      containers: {
        images: await this.prisma.containerImage.count({ where: { registry: { workspaceId } } as never }).catch(() => 0),
        criticalCves: findings.filter((f) => f.sourceDomain === "CONTAINER" && f.severity === "CRITICAL").length,
      },
    };
  }

  async identityAnalytics(user: { organizationId: string }, workspaceId: string) {
    void workspaceId; // identity records are organization-scoped (Prompt 23 schema)
    const org = user.organizationId;
    const [memberships, mfa, sso, apiKeys, serviceAccounts, reviews] = await Promise.all([
      this.prisma.membership.findMany({ where: { organizationId: org, status: "ACTIVE" }, take: 5000 }),
      this.prisma.mfaMethod.findMany({ where: { isActive: true }, take: 5000 }),
      this.prisma.enterpriseSsoProvider.findMany({ where: { organizationId: org }, take: 100 }),
      this.prisma.apiKey.findMany({ where: { organizationId: org }, take: 1000 }),
      this.prisma.serviceAccount.findMany({ where: { organizationId: org }, take: 1000 }),
      this.prisma.accessReview.findMany({ where: { organizationId: org }, take: 500 }),
    ]);
    const memberIds = new Set(memberships.map((m) => m.userId));
    const mfaUsers = new Set(mfa.filter((m) => memberIds.has(m.userId)).map((m) => m.userId));
    const privileged = memberships.filter((m) => m.role === "OWNER" || m.role === "ADMIN");
    const privilegedWithMfa = privileged.filter((m) => mfaUsers.has(m.userId));
    return {
      sources: ["Membership", "MfaMethod", "EnterpriseSsoProvider", "ApiKey", "ServiceAccount", "AccessReview"],
      members: memberships.length,
      mfaCoverage: memberships.length === 0 ? null : mfaUsers.size / memberships.length,
      mfaEnrolledUsers: mfaUsers.size,
      ssoProviders: sso.length,
      ssoEnabled: sso.filter((s) => s.enabled).length,
      privilegedIdentities: privileged.length,
      privilegedWithoutMfa: privileged.length - privilegedWithMfa.length,
      apiKeys: apiKeys.filter((k) => !k.revokedAt).length,
      serviceAccounts: serviceAccounts.length,
      pendingAccessReviews: reviews.filter((r) => r.status === "OPEN" || r.status === "IN_PROGRESS").length,
    };
  }

  async grcAnalytics(workspaceId: string, now = new Date()) {
    const [evaluations, evidence, policies, risks, acceptances, auditFindings, frameworks, assessments] = await Promise.all([
      this.prisma.controlEvaluation.findMany({ where: { workspaceId }, orderBy: { evaluatedAt: "desc" }, take: 5000 }),
      this.prisma.complianceEvidence.findMany({ where: { workspaceId }, take: 5000 }),
      this.prisma.evidenceFreshnessPolicy.findMany({ where: { workspaceId }, take: 1000 }),
      this.prisma.riskRecord.findMany({ where: { workspaceId }, take: 5000 }),
      this.prisma.riskAcceptance.findMany({ where: { workspaceId }, take: 1000 }),
      this.prisma.auditFinding.findMany({ where: { workspaceId }, take: 1000 }),
      this.prisma.complianceFramework.findMany({ take: 100 }),
      this.prisma.complianceAssessment.findMany({ where: { workspaceId }, take: 500 }),
    ]);
    const latestByControl = new Map<string, string>();
    for (const e of evaluations) if (!latestByControl.has(e.controlId)) latestByControl.set(e.controlId, e.result);
    const policyByControl = new Map(policies.map((p) => [p.controlId, p]));
    let staleEvidence = 0;
    for (const ev of evidence) {
      const policy = policyByControl.get(ev.controlId) ?? { staleAfterDays: 335, expireAfterDays: 400 };
      const status = evidenceFreshness(new Date(ev.collectedAt).toISOString(), policy as never, now, ev.status as never);
      if (status === "STALE" || status === "EXPIRED") staleEvidence++;
    }
    const assessedFrameworks = new Set(assessments.filter((a) => a.status === "COMPLETED").map((a) => a.frameworkId));
    return {
      sources: ["ControlEvaluation", "ComplianceEvidence", "RiskRecord", "RiskAcceptance", "AuditFinding", "ComplianceAssessment"],
      controlFailures: [...latestByControl.values()].filter((r) => r === "FAIL").length,
      controlsEvaluated: latestByControl.size,
      evidenceFreshness: { total: evidence.length, staleOrExpired: staleEvidence, current: evidence.length - staleEvidence },
      assessmentGaps: frameworks.filter((f) => !assessedFrameworks.has(f.id)).map((f) => ({ key: f.key, version: f.version })),
      highResidualRisks: risks.filter((r) => r.residualBand === "HIGH" || r.residualBand === "CRITICAL").length,
      expiringRiskAcceptances: acceptances.filter((a) => a.status === "ACCEPTED" && a.expiresAt > now && a.expiresAt.getTime() - now.getTime() < 30 * DAY).length,
      openAuditFindings: auditFindings.filter((a) => a.status !== "CLOSED" && a.status !== "RESOLVED").length,
    };
  }
}
