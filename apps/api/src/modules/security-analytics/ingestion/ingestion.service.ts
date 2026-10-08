import { Inject, Injectable } from "@nestjs/common";
import {
  projectFindingLifecycle, validateAnalyticsEvent, type AnalyticsEventInput,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AnalyticsStoreService } from "../storage/analytics-store.service";

/**
 * Analytics ingestion (Prompt 27 §8–§13).
 *
 * Operational change → transactional outbox / finding history →
 * THIS consumer → validate → normalize → enrich → store → project.
 * Idempotent on the stable eventId (§9/§131); invalid events go to
 * the bounded dead-letter with their validation codes and never
 * block the stream (§11); checkpoints track each source partition
 * (§10). Projections are pure functions of the landed event history,
 * so replay/rebuild is deterministic (§117/§133).
 */

const HISTORY_EVENT_MAP: Record<string, string> = {
  CREATED: "FINDING_CREATED",
  CONFIRMED: "FINDING_VERIFIED",
  RESOLVED: "FINDING_RESOLVED",
  REOPENED: "FINDING_REOPENED",
  SEVERITY_CHANGED: "RISK_CHANGED",
  RISK_RECALCULATED: "RISK_CHANGED",
  REVIEWED: "FINDING_UPDATED",
  FALSE_POSITIVE: "FINDING_UPDATED",
  ACCEPTED_RISK: "FINDING_UPDATED",
  CORRELATED: "FINDING_UPDATED",
};

const OUTBOX_EVENT_MAP: Record<string, string> = {
  FINDING_CREATED: "FINDING_CREATED",
  FINDING_UPDATED: "FINDING_UPDATED",
  FINDING_RESOLVED: "FINDING_RESOLVED",
  FINDING_REOPENED: "FINDING_REOPENED",
  SCAN_STARTED: "SCAN_STARTED",
  SCAN_COMPLETED: "SCAN_COMPLETED",
  SCAN_FAILED: "SCAN_FAILED",
  ASSET_DISCOVERED: "ASSET_DISCOVERED",
  CONTROL_FAILED: "CONTROL_FAILED",
  CONTROL_RECOVERED: "CONTROL_RECOVERED",
};

export interface IngestOutcome { stored: number; duplicates: number; rejected: number; errors: string[] }

@Injectable()
export class IngestionService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly store: AnalyticsStoreService,
  ) {}

  /**
   * Land a batch of canonical events for one workspace. Each event is
   * validated BEFORE storage (§12); failures are quarantined with a
   * sanitized summary — identifiers and codes only, never raw bodies
   * that could carry secrets (§111).
   */
  async ingestBatch(scope: { organizationId: string; workspaceId: string }, rawEvents: readonly Record<string, unknown>[]): Promise<IngestOutcome> {
    const outcome: IngestOutcome = { stored: 0, duplicates: 0, rejected: 0, errors: [] };
    const affectedFindings = new Set<string>();
    for (const raw of rawEvents) {
      const input = raw as unknown as AnalyticsEventInput;
      // Tenant context is part of validity: an event naming another
      // tenant is rejected, never re-homed (§12/§148).
      if (input && (input.organizationId !== scope.organizationId || input.workspaceId !== scope.workspaceId)) {
        outcome.rejected++;
        await this.deadLetter(scope.workspaceId, input, ["TENANT_CONTEXT_MISMATCH"]);
        continue;
      }
      const errors = validateAnalyticsEvent(input);
      if (errors.length) {
        outcome.rejected++;
        outcome.errors.push(...errors);
        await this.deadLetter(scope.workspaceId, input, errors);
        continue;
      }
      const result = await this.store.writeEvent(input);
      if (result.stored) { outcome.stored++; if (input.findingId) affectedFindings.add(input.findingId); }
      else outcome.duplicates++;
    }
    for (const findingId of affectedFindings) await this.reprojectFinding(scope, findingId);
    return outcome;
  }

  private async deadLetter(workspaceId: string | null, input: AnalyticsEventInput | undefined, errors: string[]): Promise<void> {
    await this.prisma.analyticsDeadLetterEvent.create({
      data: {
        workspaceId: workspaceId ?? (input?.workspaceId as string) ?? null,
        eventId: input?.eventId ?? null,
        sourceType: input?.sourceType ?? "UNKNOWN",
        rawSummary: {
          eventType: input?.eventType ?? null, resourceType: input?.resourceType ?? null,
          resourceId: input?.resourceId ?? null,
        } as never,
        errors: errors as never,
        status: "QUARANTINED",
      },
    });
  }

  /** Consume the transactional outbox (§8) from the partition checkpoint. */
  async consumeOutbox(scope: { organizationId: string; workspaceId: string }): Promise<IngestOutcome> {
    const checkpoint = await this.getCheckpoint(scope.workspaceId, "OUTBOX");
    const rows = await this.prisma.securityEventOutbox.findMany({
      where: { workspaceId: scope.workspaceId }, orderBy: { createdAt: "asc" }, take: 500,
    });
    const cursor = checkpoint?.lastEventKey ?? "";
    const fresh = rows.filter((r) => `${r.createdAt.toISOString()}|${r.id}` > cursor);
    const events: AnalyticsEventInput[] = [];
    let rejected = 0;
    for (const row of fresh) {
      const mapped = OUTBOX_EVENT_MAP[row.eventType];
      if (!mapped) {
        rejected++;
        await this.deadLetter(scope.workspaceId, undefined, ["EVENT_TYPE_UNKNOWN"]);
        continue;
      }
      const payload = (row.payload ?? {}) as Record<string, unknown>;
      events.push({
        eventId: `outbox:${row.eventId}`,
        organizationId: scope.organizationId, workspaceId: scope.workspaceId,
        eventType: mapped, eventTime: row.createdAt.toISOString(),
        sourceType: "OUTBOX", sourceId: row.id,
        resourceType: row.resourceType, resourceId: row.resourceId,
        findingId: row.resourceType === "FINDING" ? row.resourceId : undefined,
        scanId: row.resourceType === "SCAN" ? row.resourceId : undefined,
        severity: (payload.severity as string) ?? null,
        riskScore: typeof payload.riskScore === "number" ? payload.riskScore : null,
        attributes: { outboxEventType: row.eventType },
      });
    }
    const outcome = await this.ingestBatch(scope, events as unknown as Record<string, unknown>[]);
    outcome.rejected += rejected;
    const last = fresh[fresh.length - 1];
    await this.saveCheckpoint(scope.workspaceId, "OUTBOX", last ? `${last.createdAt.toISOString()}|${last.id}` : cursor, outcome);
    return outcome;
  }

  /** Project the append-only finding history (§37 trail) into analytics events. */
  async consumeFindingHistory(scope: { organizationId: string; workspaceId: string }): Promise<IngestOutcome> {
    const checkpoint = await this.getCheckpoint(scope.workspaceId, "FINDING_HISTORY");
    const rows = await this.prisma.findingHistory.findMany({
      where: { workspaceId: scope.workspaceId }, orderBy: { createdAt: "asc" }, take: 1000,
    });
    const cursor = checkpoint?.lastEventKey ?? "";
    const fresh = rows.filter((r) => `${r.createdAt.toISOString()}|${r.id}` > cursor);
    const events: AnalyticsEventInput[] = [];
    for (const row of fresh) {
      const finding = await this.prisma.finding.findFirst({ where: { id: row.findingId, workspaceId: scope.workspaceId } });
      if (!finding) continue;
      const mapped = HISTORY_EVENT_MAP[row.event] ?? "FINDING_UPDATED";
      events.push({
        eventId: `history:${row.id}`,
        organizationId: scope.organizationId, workspaceId: scope.workspaceId,
        eventType: mapped, eventTime: row.createdAt.toISOString(),
        sourceType: "FINDING_HISTORY", sourceId: row.id,
        resourceType: "FINDING", resourceId: finding.id,
        assetId: finding.assetId ?? null, findingId: finding.id, scanId: finding.scanId,
        severity: finding.severity, priority: finding.priority ?? null,
        riskScore: finding.riskScore ?? null,
        classification: finding.dataSensitivity ?? "INTERNAL",
        attributes: {
          cwe: finding.cwe ?? null, cve: finding.cve ?? null,
          lifecycleStatus: finding.lifecycleStatus, historyEvent: row.event,
          repositoryId: finding.repositoryId ?? null,
          kevListed: finding.kevListed, epssScore: finding.epssScore ?? null,
        },
      });
    }
    const outcome = await this.ingestBatch(scope, events as unknown as Record<string, unknown>[]);
    const last = fresh[fresh.length - 1];
    await this.saveCheckpoint(scope.workspaceId, "FINDING_HISTORY", last ? `${last.createdAt.toISOString()}|${last.id}` : cursor, outcome);
    return outcome;
  }

  /** Full ingestion pass over every built-in producer partition. */
  async runAll(scope: { organizationId: string; workspaceId: string }): Promise<{ outbox: IngestOutcome; history: IngestOutcome }> {
    const outbox = await this.consumeOutbox(scope);
    const history = await this.consumeFindingHistory(scope);
    return { outbox, history };
  }

  /**
   * (Re)build the lifecycle + risk-history projections for one
   * finding from its landed events. Pure projection → rebuilds are
   * deterministic (§117/§133).
   */
  async reprojectFinding(scope: { organizationId: string; workspaceId: string }, findingId: string): Promise<void> {
    const events = await this.store.timeline(scope, { findingId });
    const inputs = events.map((e) => ({
      eventId: e.eventId, organizationId: e.organizationId, workspaceId: e.workspaceId,
      eventType: e.eventType, eventTime: e.eventTime.toISOString(), sourceType: e.sourceType,
      sourceId: e.sourceId, resourceType: e.resourceType, resourceId: e.resourceId,
      assetId: e.assetId, findingId: e.findingId, scanId: e.scanId, severity: e.severity,
      priority: e.priority, riskScore: e.riskScore, classification: e.classification,
      schemaVersion: e.schemaVersion, attributes: (e.attributes ?? {}) as Record<string, unknown>,
    }));
    const projection = projectFindingLifecycle(inputs);
    if (!projection) return;
    const data = {
      firstSeenAt: new Date(projection.firstSeenAt), lastSeenAt: new Date(projection.lastSeenAt),
      triagedAt: projection.triagedAt ? new Date(projection.triagedAt) : null,
      verifiedAt: projection.verifiedAt ? new Date(projection.verifiedAt) : null,
      resolvedAt: projection.resolvedAt ? new Date(projection.resolvedAt) : null,
      reopenedAt: projection.reopenedAt ? new Date(projection.reopenedAt) : null,
      regressionCount: projection.regressionCount, remediationSeconds: projection.remediationSeconds,
      currentStatus: projection.currentStatus, severity: projection.severity,
      cwe: projection.cwe, cve: projection.cve, assetId: projection.assetId,
      repositoryId: projection.repositoryId, rebuiltAt: new Date(),
    };
    const existing = await this.prisma.findingLifecycleProjection.findFirst({
      where: { workspaceId: scope.workspaceId, findingId },
    });
    if (existing) {
      await this.prisma.findingLifecycleProjection.update({ where: { id: existing.id }, data });
    } else {
      await this.prisma.findingLifecycleProjection.create({ data: { workspaceId: scope.workspaceId, findingId, ...data } });
    }
    // Risk history points — one per risk-bearing event, deduped by
    // source event. Existing source ids are loaded ONCE per
    // reprojection (indexed in production) instead of probed per event.
    const existingRisk = await this.prisma.riskHistoryProjection.findMany({
      where: { workspaceId: scope.workspaceId, findingId }, take: 100_000,
    });
    const seenRiskEvents = new Set(existingRisk.map((r) => r.sourceEventId));
    for (const e of events) {
      if (e.riskScore == null && e.eventType !== "KEV_DETECTED" && e.eventType !== "EPSS_CHANGED") continue;
      if (seenRiskEvents.has(e.eventId)) continue;
      seenRiskEvents.add(e.eventId);
      const attrs = (e.attributes ?? {}) as Record<string, unknown>;
      await this.prisma.riskHistoryProjection.create({
        data: {
          workspaceId: scope.workspaceId, findingId: e.findingId, assetId: e.assetId,
          recordedAt: e.eventTime, riskScore: e.riskScore, priority: e.priority,
          kevListed: attrs.kevListed === true, epssScore: typeof attrs.epssScore === "number" ? attrs.epssScore : null,
          verificationState: e.eventType === "FINDING_VERIFIED" ? "CONFIRMED" : null,
          sourceEventId: e.eventId,
        },
      });
    }
  }

  /** §117: rebuild every projection in the workspace from landed events. */
  async rebuildProjections(scope: { organizationId: string; workspaceId: string }): Promise<{ findings: number }> {
    const events = await this.store.query(scope, { take: 10_000 });
    const findingIds = [...new Set(events.map((e) => e.findingId).filter(Boolean))] as string[];
    for (const findingId of findingIds) await this.reprojectFinding(scope, findingId);
    return { findings: findingIds.length };
  }

  private async getCheckpoint(workspaceId: string, partition: string) {
    return this.prisma.analyticsIngestionCheckpoint.findFirst({
      where: { workspaceId, consumer: "ANALYTICS_INGESTION", partition },
    });
  }

  private async saveCheckpoint(workspaceId: string, partition: string, cursor: string, outcome: IngestOutcome): Promise<void> {
    const existing = await this.getCheckpoint(workspaceId, partition);
    const data = {
      lastEventKey: cursor || null, lastEventAt: new Date(), status: "IDLE",
      processed: (existing?.processed ?? 0) + outcome.stored + outcome.duplicates,
      rejected: (existing?.rejected ?? 0) + outcome.rejected,
    };
    if (existing) await this.prisma.analyticsIngestionCheckpoint.update({ where: { id: existing.id }, data });
    else await this.prisma.analyticsIngestionCheckpoint.create({
      data: { workspaceId, consumer: "ANALYTICS_INGESTION", partition, ...data },
    });
  }
}
