import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";

/**
 * Analytics health & observability (§118–§121).
 *
 * Reports ingestion lag, dead-letter volume, search-index lag,
 * aggregation freshness and projection errors — measured from the
 * lake's own records. Performance budgets are stated as TARGETS
 * (§121); nothing here claims a benchmark that was not measured.
 */
@Injectable()
export class AnalyticsHealthService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async health(workspaceId: string) {
    const [checkpoints, deadLetters, events, documents, latestEvent, latestDoc, latestSnapshot, reindexJobs] = await Promise.all([
      this.prisma.analyticsIngestionCheckpoint.findMany({ where: { workspaceId } }),
      this.prisma.analyticsDeadLetterEvent.count({ where: { workspaceId, status: "QUARANTINED" } }),
      this.prisma.securityAnalyticsEvent.count({ where: { workspaceId } }),
      this.prisma.securitySearchDocument.count({ where: { workspaceId } }),
      this.prisma.securityAnalyticsEvent.findFirst({ where: { workspaceId }, orderBy: { ingestedAt: "desc" } }),
      this.prisma.securitySearchDocument.findFirst({ where: { workspaceId }, orderBy: { updatedAt: "desc" } }),
      this.prisma.analyticsDashboardSnapshot.findFirst({ where: { workspaceId }, orderBy: { capturedAt: "desc" } }),
      this.prisma.securitySearchReindexJob.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 5 }),
    ]);
    const now = Date.now();
    const ingestionLagSeconds = latestEvent ? Math.max(0, Math.round((now - latestEvent.ingestedAt.getTime()) / 1000)) : null;
    const searchIndexLagSeconds = latestDoc ? Math.max(0, Math.round((now - latestDoc.updatedAt.getTime()) / 1000)) : null;
    const alerts: string[] = [];
    if (deadLetters > 25) alerts.push("HIGH_DEAD_LETTER_RATE");
    if (checkpoints.some((c) => c.status === "STALLED" || c.status === "ERROR")) alerts.push("INGESTION_STALLED");
    if (events > 0 && documents === 0) alerts.push("SEARCH_INDEX_EMPTY");
    return {
      status: alerts.length ? "DEGRADED" : "OK",
      events, documents, deadLetterCount: deadLetters,
      checkpoints: checkpoints.map((c) => ({
        partition: c.partition, status: c.status, processed: c.processed, rejected: c.rejected, lastEventAt: c.lastEventAt,
      })),
      ingestionLagSeconds, searchIndexLagSeconds,
      aggregationFreshness: latestSnapshot ? latestSnapshot.capturedAt : null,
      projectionErrors: deadLetters,
      recentReindexJobs: reindexJobs.map((j) => ({ id: j.id, status: j.status, indexedCount: j.indexedCount, documentType: j.documentType })),
      alerts,
      performanceBudgets: {
        note: "Bounded targets (§121) — targets, not measured benchmark claims.",
        searchP95Ms: 750, dashboardP95Ms: 1500, timelineP95Ms: 750, aggregationP95Ms: 2000,
        maxCandidatesPerSearch: 1000, maxEventsPerQuery: 10_000,
      },
    };
  }
}
