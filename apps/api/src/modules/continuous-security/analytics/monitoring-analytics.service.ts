import { Inject, Injectable } from "@nestjs/common";
import { rollupPostureSnapshots } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireContinuousPermission } from "../permissions";

/**
 * Monitoring analytics, scheduler health and the AI daily summary
 * (Prompt 22 §76/§77, §89–§92).
 *
 * The daily summary is GROUNDED: it is assembled from the immutable
 * posture snapshot + drift records of that day, cites their ids, and
 * is labelled RULE_BASED — the same honesty posture as Prompt 21
 * (no AI provider is configured; nothing here pretends otherwise).
 * The copilot may summarize posture, but it can never launch
 * intrusive scans (§75): this service has no execution surface.
 */
@Injectable()
export class MonitoringAnalyticsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  /** §89/§90: scheduler + monitoring observability for one workspace. */
  async health(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 3600_000);
    const [lease, dueCount, overdueCount, runs24h, failed24h, deadLetters, activeSchedules, latestSnapshot] = await Promise.all([
      this.prisma.schedulerLease.findUnique({ where: { scope: "continuous-scheduler" } }),
      this.prisma.securitySchedule.count({ where: { workspaceId, enabled: true, paused: false, nextRunAt: { lte: now } } }),
      this.prisma.securitySchedule.count({ where: { workspaceId, enabled: true, paused: false, nextRunAt: { lt: new Date(now.getTime() - 3600_000) } } }),
      this.prisma.scheduleRun.count({ where: { workspaceId, createdAt: { gte: dayAgo } } }),
      this.prisma.scheduleRun.count({ where: { workspaceId, createdAt: { gte: dayAgo }, status: { in: ["FAILED", "BLOCKED"] } } }),
      this.prisma.deadLetterJob.count({ where: { queue: "scheduled-runs", createdAt: { gte: dayAgo } } }),
      this.prisma.securitySchedule.count({ where: { workspaceId, enabled: true } }),
      this.prisma.securityPostureSnapshot.findFirst({ where: { workspaceId }, orderBy: { capturedAt: "desc" } }),
    ]);
    const leaseStale = lease ? now.getTime() - new Date(lease.heartbeatAt).getTime() > 5 * 60_000 : true;
    return {
      scheduler: {
        leaseOwner: lease?.owner ?? null,
        leaseUntil: lease?.leaseUntil ?? null,
        heartbeatAt: lease?.heartbeatAt ?? null,
        stale: leaseStale,
        status: !lease ? "NEVER_TICKED" : leaseStale ? "STALE" : "ACTIVE",
      },
      workspaceId,
      activeSchedules, dueNow: dueCount, overdueSchedules: overdueCount,
      runsLast24h: runs24h, failedOrBlockedLast24h: failed24h, deadLettersLast24h: deadLetters,
      latestPostureSnapshotAt: latestSnapshot?.capturedAt ?? null,
      note: "the scheduler advances when tick() is invoked (deployment timer or admin action); runs are materialized only through the gated paths",
    };
  }

  /** §92: posture rollups over the immutable snapshot history. */
  async postureRollups(user: RequestUser, workspaceId: string, granularity: "HOURLY" | "DAILY" | "WEEKLY" = "DAILY") {
    requireContinuousPermission(user, "VIEW_POSTURE_HISTORY");
    const snapshots = await this.prisma.securityPostureSnapshot.findMany({
      where: { workspaceId }, orderBy: { capturedAt: "asc" }, take: 2000,
    });
    const rolled = rollupPostureSnapshots(
      snapshots.map((s) => ({ capturedAt: s.capturedAt, riskScore: s.riskScore })),
      granularity,
    );
    return {
      granularity,
      buckets: rolled.map((r) => {
        const snap = snapshots.find((s) => s.capturedAt === r.snapshot.capturedAt);
        return {
          bucketStart: r.bucketStart, snapshotId: snap?.id, capturedAt: r.snapshot.capturedAt,
          riskScore: r.snapshot.riskScore, findingCount: snap?.findingCount,
          assetCount: snap?.assetCount, kevCount: snap?.kevCount,
        };
      }),
    };
  }

  /** §76/§77: grounded daily summary over stored records only. */
  async generateDailySummary(user: RequestUser, workspaceId: string, date: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const dayStart = new Date(`${date}T00:00:00.000Z`);
    const dayEnd = new Date(dayStart.getTime() + 24 * 3600_000);
    const existing = await this.prisma.aiDailySecuritySummary.findFirst({ where: { workspaceId, date } });
    if (existing) return existing;
    const [snapshot, surface, findingDrift, riskDrift, runs] = await Promise.all([
      this.prisma.securityPostureSnapshot.findFirst({ where: { workspaceId, capturedAt: { gte: dayStart, lt: dayEnd } }, orderBy: { capturedAt: "desc" } }),
      this.prisma.attackSurfaceChange.findMany({ where: { workspaceId, detectedAt: { gte: dayStart, lt: dayEnd } }, take: 100 }),
      this.prisma.findingDriftEvent.findMany({ where: { workspaceId, detectedAt: { gte: dayStart, lt: dayEnd } }, take: 100 }),
      this.prisma.riskDriftEvent.findMany({ where: { workspaceId, detectedAt: { gte: dayStart, lt: dayEnd } }, take: 100 }),
      this.prisma.scheduleRun.findMany({ where: { workspaceId, createdAt: { gte: dayStart, lt: dayEnd } }, take: 200 }),
    ]);
    const citations: string[] = [
      ...(snapshot ? [snapshot.id] : []),
      ...surface.map((e) => e.id), ...findingDrift.map((e) => e.id), ...riskDrift.map((e) => e.id),
    ];
    const highlights: string[] = [];
    if (snapshot) highlights.push(`Posture snapshot: ${snapshot.findingCount} findings across ${snapshot.assetCount} assets; ${snapshot.kevCount} KEV-listed; risk score ${snapshot.riskScore ?? "not computable (no scored findings)"}.`);
    else highlights.push("No posture snapshot was captured on this date — the summary cites drift and run records only.");
    if (surface.length > 0) highlights.push(`${surface.length} attack-surface change(s), including ${surface.filter((e) => e.priority === "HIGH").length} high-priority exposure change(s). New assets are DISCOVERED only — never auto-authorized.`);
    if (findingDrift.length > 0) highlights.push(`${findingDrift.length} finding drift event(s): ${findingDrift.filter((e) => e.type === "REOPENED").length} reopened, ${findingDrift.filter((e) => e.type === "RESOLVED").length} resolved.`);
    if (riskDrift.length > 0) highlights.push(`${riskDrift.length} risk drift event(s) from intelligence movement (KEV/EPSS/CVSS) — affected findings were re-scored without re-scanning.`);
    const blocked = runs.filter((r) => r.status === "BLOCKED" || r.status === "SKIPPED");
    if (blocked.length > 0) highlights.push(`${blocked.length} scheduled run(s) were blocked or skipped by policy gates (authorization, windows, budgets) — gates are never bypassed.`);
    const summary = {
      date,
      highlights,
      counts: {
        attackSurfaceChanges: surface.length, findingDrift: findingDrift.length,
        riskDrift: riskDrift.length, scheduleRuns: runs.length,
        blockedOrSkippedRuns: blocked.length,
      },
      posture: snapshot ? { riskScore: snapshot.riskScore, findingCount: snapshot.findingCount, assetCount: snapshot.assetCount, kevCount: snapshot.kevCount } : null,
    };
    return this.prisma.aiDailySecuritySummary.create({
      data: {
        workspaceId, date, snapshotId: snapshot?.id, generator: "RULE_BASED",
        summary: summary as never, citations: citations as never,
      },
    });
  }

  async listDailySummaries(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.aiDailySecuritySummary.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 60 });
  }

  /** §91: retention is policy, enforced by an operator job — this
   *  endpoint reports the policy and current footprint; it never
   *  deletes silently from a read path. */
  async retentionReport(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const [snapshots, runs, notifications, executions] = await Promise.all([
      this.prisma.securityPostureSnapshot.count({ where: { workspaceId } }),
      this.prisma.scheduleRun.count({ where: { workspaceId } }),
      this.prisma.securityNotification.count({ where: { workspaceId } }),
      this.prisma.workflowExecution.count({ where: { workspaceId } }),
    ]);
    return {
      policy: {
        postureSnapshots: "retain 13 months (immutable history)",
        scheduleRuns: "retain 12 months",
        notifications: "retain 6 months",
        workflowExecutions: "retain 12 months",
        summaries: "retain 13 months",
      },
      footprint: { postureSnapshots: snapshots, scheduleRuns: runs, notifications, workflowExecutions: executions },
      note: "retention windows are enforced by an operator maintenance job; snapshots are immutable while retained (§32)",
    };
  }
}
