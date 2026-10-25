import { Inject, Injectable } from "@nestjs/common";
import {
  analyticsEventChecksum, validateAnalyticsEvent, type AnalyticsEventInput,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";

/**
 * SecurityAnalyticsStore (§14) — the storage abstraction over the
 * initial PostgreSQL backend (§15). The interface (writeEvent /
 * writeBatch / query / aggregate / timeline / deleteByRetention /
 * healthCheck) is backend-shaped so a future ClickHouse/OpenSearch
 * adapter can replace the Prisma implementation without touching
 * consumers. Writes are idempotent on eventId (§9): a duplicate
 * delivery returns { duplicate: true } and changes nothing.
 */
@Injectable()
export class AnalyticsStoreService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async writeEvent(input: AnalyticsEventInput): Promise<{ stored: boolean; duplicate: boolean; id?: string }> {
    const existing = await this.prisma.securityAnalyticsEvent.findUnique({ where: { eventId: input.eventId } });
    if (existing) return { stored: false, duplicate: true, id: existing.id };
    const row = await this.prisma.securityAnalyticsEvent.create({
      data: {
        eventId: input.eventId, organizationId: input.organizationId, workspaceId: input.workspaceId,
        eventType: input.eventType, eventTime: new Date(input.eventTime), sourceType: input.sourceType,
        sourceId: input.sourceId ?? null, resourceType: input.resourceType, resourceId: input.resourceId,
        assetId: input.assetId ?? null, findingId: input.findingId ?? null, scanId: input.scanId ?? null,
        severity: input.severity ?? null, priority: input.priority ?? null, riskScore: input.riskScore ?? null,
        classification: input.classification ?? "INTERNAL", schemaVersion: input.schemaVersion ?? "1.0",
        attributes: (input.attributes ?? {}) as never, checksum: analyticsEventChecksum(input),
      },
    });
    return { stored: true, duplicate: false, id: row.id };
  }

  async writeBatch(inputs: readonly AnalyticsEventInput[]): Promise<{ stored: number; duplicates: number }> {
    let stored = 0; let duplicates = 0;
    for (const input of inputs) {
      const r = await this.writeEvent(input);
      if (r.stored) stored++; else duplicates++;
    }
    return { stored, duplicates };
  }

  /** Tenant-scoped event query — organization AND workspace are mandatory (§23 analogue). */
  async query(scope: { organizationId: string; workspaceId: string }, filter: {
    eventTypes?: string[]; assetId?: string; findingId?: string; from?: Date; to?: Date; take?: number;
  } = {}) {
    return this.prisma.securityAnalyticsEvent.findMany({
      where: {
        organizationId: scope.organizationId, workspaceId: scope.workspaceId,
        ...(filter.eventTypes ? { eventType: { in: filter.eventTypes } } : {}),
        ...(filter.assetId ? { assetId: filter.assetId } : {}),
        ...(filter.findingId ? { findingId: filter.findingId } : {}),
        ...(filter.from || filter.to ? { eventTime: { ...(filter.from ? { gte: filter.from } : {}), ...(filter.to ? { lte: filter.to } : {}) } } : {}),
      } as never,
      orderBy: { eventTime: "asc" },
      take: Math.min(filter.take ?? 2000, 10_000),
    });
  }

  /** Timeline for one resource, ordered by eventTime (§132) — never by arrival. */
  async timeline(scope: { organizationId: string; workspaceId: string }, filter: { assetId?: string; findingId?: string }) {
    return this.query(scope, filter);
  }

  async aggregate(scope: { organizationId: string; workspaceId: string }, eventTypes?: string[]): Promise<{ total: number; byType: Record<string, number> }> {
    const rows = await this.query(scope, { eventTypes, take: 10_000 });
    const byType: Record<string, number> = {};
    for (const r of rows) byType[r.eventType] = (byType[r.eventType] ?? 0) + 1;
    return { total: rows.length, byType };
  }

  /** Retention deletion — lake-owned events only (§114). */
  async deleteByRetention(workspaceId: string, cutoff: Date, restrictedCutoff: Date): Promise<number> {
    const normal = await this.prisma.securityAnalyticsEvent.deleteMany({
      where: { workspaceId, eventTime: { lt: cutoff }, classification: { not: "RESTRICTED" } } as never,
    });
    const restricted = await this.prisma.securityAnalyticsEvent.deleteMany({
      where: { workspaceId, eventTime: { lt: restrictedCutoff }, classification: "RESTRICTED" } as never,
    });
    return (normal.count ?? 0) + (restricted.count ?? 0);
  }

  async healthCheck(workspaceId: string): Promise<{ status: string; events: number }> {
    const events = await this.prisma.securityAnalyticsEvent.count({ where: { workspaceId } });
    return { status: "ok", events };
  }
}

export { validateAnalyticsEvent };
