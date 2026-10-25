import { Inject, Injectable } from "@nestjs/common";
import { isExpired, type AnalyticsRetentionPolicyInput } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { IndexingService } from "../search/indexing.service";
import { IngestionService } from "../ingestion/ingestion.service";
import { AnalyticsStoreService } from "../storage/analytics-store.service";

export const DEFAULT_RETENTION: AnalyticsRetentionPolicyInput = {
  eventRetentionDays: 730, searchDocRetentionDays: 730,
  snapshotRetentionDays: 365, restrictedEventRetentionDays: 365,
};

/**
 * Retention, reindexing and rebuild (§113–§117, §143–§144).
 *
 * Retention deletes ONLY lake-owned records (analytics events,
 * search documents, lake snapshots). Audit logs and compliance
 * evidence are not lake records and have no deletion path here
 * (§114/§148).
 */
@Injectable()
export class RetentionService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly indexing: IndexingService,
    private readonly ingestion: IngestionService,
    private readonly store: AnalyticsStoreService,
  ) {}

  async getPolicy(workspaceId: string): Promise<AnalyticsRetentionPolicyInput> {
    const row = await this.prisma.analyticsRetentionPolicy.findFirst({ where: { workspaceId } });
    if (!row) return DEFAULT_RETENTION;
    return {
      eventRetentionDays: row.eventRetentionDays, searchDocRetentionDays: row.searchDocRetentionDays,
      snapshotRetentionDays: row.snapshotRetentionDays, restrictedEventRetentionDays: row.restrictedEventRetentionDays,
    };
  }

  async upsertPolicy(workspaceId: string, body: Partial<AnalyticsRetentionPolicyInput>) {
    const current = await this.getPolicy(workspaceId);
    const next = { ...current, ...body };
    const existing = await this.prisma.analyticsRetentionPolicy.findFirst({ where: { workspaceId } });
    if (existing) return this.prisma.analyticsRetentionPolicy.update({ where: { id: existing.id }, data: next });
    return this.prisma.analyticsRetentionPolicy.create({ data: { workspaceId, ...next } });
  }

  async runRetention(workspaceId: string, now = new Date()): Promise<{ eventsDeleted: number; documentsDeleted: number; snapshotsDeleted: number }> {
    const policy = await this.getPolicy(workspaceId);
    const eventsDeleted = await this.store.deleteByRetention(
      workspaceId,
      new Date(now.getTime() - policy.eventRetentionDays * 86_400_000),
      new Date(now.getTime() - policy.restrictedEventRetentionDays * 86_400_000),
    );
    const docs = await this.prisma.securitySearchDocument.findMany({ where: { workspaceId }, take: 10_000 });
    let documentsDeleted = 0;
    for (const doc of docs) {
      if (isExpired(policy, "SEARCH_DOCUMENT", doc.classification, doc.updatedAt, now)) {
        await this.prisma.securitySearchDocument.delete({ where: { id: doc.id } });
        documentsDeleted++;
      }
    }
    const snapshots = await this.prisma.analyticsDashboardSnapshot.findMany({ where: { workspaceId }, take: 5000 });
    let snapshotsDeleted = 0;
    for (const snap of snapshots) {
      if (isExpired(policy, "SNAPSHOT", null, snap.capturedAt, now)) {
        await this.prisma.analyticsDashboardSnapshot.delete({ where: { id: snap.id } });
        snapshotsDeleted++;
      }
    }
    return { eventsDeleted, documentsDeleted, snapshotsDeleted };
  }

  /** §115/§116/§144: controlled reindex — rebuild via the same indexing path. */
  async runReindex(scope: { organizationId: string; workspaceId: string }, requestedBy: string, documentType?: string) {
    const job = await this.prisma.securitySearchReindexJob.create({
      data: { workspaceId: scope.workspaceId, documentType: documentType ?? null, status: "RUNNING", requestedBy, startedAt: new Date() },
    });
    try {
      if (documentType) {
        await this.prisma.securitySearchDocument.deleteMany({ where: { workspaceId: scope.workspaceId, documentType } });
      } else {
        await this.prisma.securitySearchDocument.deleteMany({ where: { workspaceId: scope.workspaceId } });
      }
      const result = await this.indexing.indexWorkspace(scope, documentType);
      const remaining = await this.prisma.securitySearchDocument.count({ where: { workspaceId: scope.workspaceId } });
      await this.prisma.securitySearchReindexJob.update({
        where: { id: job.id },
        data: { status: "COMPLETED", indexedCount: result.indexed, completedAt: new Date() },
      });
      return { jobId: job.id, status: "COMPLETED", indexed: result.indexed, documentsNow: remaining, byType: result.byType };
    } catch (err) {
      await this.prisma.securitySearchReindexJob.update({
        where: { id: job.id },
        data: { status: "FAILED", completedAt: new Date(), errorSummary: err instanceof Error ? err.message.slice(0, 300) : "reindex failed" },
      });
      throw err;
    }
  }

  /** §117: rebuild projections from the authoritative landed event history. */
  async rebuild(scope: { organizationId: string; workspaceId: string }) {
    return this.ingestion.rebuildProjections(scope);
  }
}
