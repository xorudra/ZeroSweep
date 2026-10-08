import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { sha256Hex } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { deriveExposure } from "../../continuous-security/snapshots/snapshot.service";
import { AnalyticsStoreService } from "../storage/analytics-store.service";

/**
 * Timelines (Prompt 27 §42/§99). Built from the append-only analytics
 * event history, ordered by eventTime — the producer's truth — so
 * out-of-order arrival never distorts the story (§132).
 */
@Injectable()
export class TimelineService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly store: AnalyticsStoreService,
  ) {}

  async assetTimeline(scope: { organizationId: string; workspaceId: string }, assetId: string) {
    const asset = await this.prisma.asset.findFirst({ where: { id: assetId, workspaceId: scope.workspaceId } });
    if (!asset) throw new NotFoundException("Asset not found");
    const events = await this.store.timeline(scope, { assetId });
    const snapshots = await this.prisma.assetSecuritySnapshot.findMany({
      where: { workspaceId: scope.workspaceId, assetId }, orderBy: { capturedAt: "asc" }, take: 200,
    });
    return {
      asset: { id: asset.id, host: asset.host, type: asset.type, criticality: asset.criticality, firstSeen: asset.firstSeen, lastSeen: asset.lastSeen },
      events: events.map((e) => ({
        eventId: e.eventId, eventType: e.eventType, eventTime: e.eventTime, ingestedAt: e.ingestedAt,
        severity: e.severity, riskScore: e.riskScore, sourceType: e.sourceType,
      })),
      snapshots: snapshots.map((s) => ({
        capturedAt: s.capturedAt, exposure: s.exposure, riskScore: s.riskScore,
        findingCounts: s.findingCounts, postureState: s.postureState,
      })),
    };
  }

  async findingTimeline(scope: { organizationId: string; workspaceId: string }, findingId: string) {
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId: scope.workspaceId } });
    if (!finding) throw new NotFoundException("Finding not found");
    const events = await this.store.timeline(scope, { findingId });
    const projection = await this.prisma.findingLifecycleProjection.findFirst({
      where: { workspaceId: scope.workspaceId, findingId },
    });
    return {
      finding: { id: finding.id, title: finding.title, severity: finding.severity, lifecycleStatus: finding.lifecycleStatus },
      events: events.map((e) => ({
        eventId: e.eventId, eventType: e.eventType, eventTime: e.eventTime, ingestedAt: e.ingestedAt,
        severity: e.severity, riskScore: e.riskScore, sourceType: e.sourceType,
      })),
      lifecycle: projection ? {
        firstSeenAt: projection.firstSeenAt, verifiedAt: projection.verifiedAt, resolvedAt: projection.resolvedAt,
        reopenedAt: projection.reopenedAt, regressionCount: projection.regressionCount,
        remediationSeconds: projection.remediationSeconds, currentStatus: projection.currentStatus,
      } : null,
    };
  }

  /** Capture point-in-time asset security snapshots (§41). */
  async captureAssetSnapshots(workspaceId: string) {
    const [assets, services, techs, findings] = await Promise.all([
      this.prisma.asset.findMany({ where: { workspaceId }, take: 10_000 }),
      this.prisma.service.findMany({ take: 20_000 }),
      this.prisma.technology.findMany({ take: 20_000 }),
      this.prisma.finding.findMany({ where: { workspaceId }, take: 10_000 }),
    ]);
    let captured = 0;
    for (const asset of assets) {
      const assetFindings = findings.filter((f) => f.assetId === asset.id);
      const open = assetFindings.filter((f) => !["RESOLVED", "REMEDIATED", "CLOSED", "FALSE_POSITIVE", "ACCEPTED_RISK"].includes(f.lifecycleStatus));
      const counts: Record<string, number> = {};
      for (const f of open) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
      const riskScore = open.length ? Math.max(...open.map((f) => f.riskScore ?? 0)) : null;
      const stateHash = sha256Hex(JSON.stringify({ counts, riskScore, criticality: asset.criticality }));
      await this.prisma.assetSecuritySnapshot.create({
        data: {
          workspaceId, assetId: asset.id, exposure: deriveExposure(asset.ip), criticality: asset.criticality,
          technologies: techs.filter((t) => t.assetId === asset.id).map((t) => ({ name: t.name, version: t.version })) as never,
          services: services.filter((s) => s.assetId === asset.id).map((s) => ({ port: s.port, protocol: s.protocol, name: s.name })) as never,
          findingCounts: counts as never, riskScore,
          postureState: open.some((f) => f.severity === "CRITICAL") ? "CRITICAL_FINDINGS_OPEN" : open.length ? "FINDINGS_OPEN" : "NO_OPEN_FINDINGS",
          stateHash,
        },
      });
      captured++;
    }
    return { captured };
  }
}
