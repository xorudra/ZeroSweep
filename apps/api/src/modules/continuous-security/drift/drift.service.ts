import { Inject, Injectable } from "@nestjs/common";
import {
  computeRiskV3, diffAssetSnapshots, diffFindingSnapshots, diffIntelSnapshots,
  type AssetSnapshotEntry, type FindingSnapshotEntry, type IntelView,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireContinuousPermission } from "../permissions";
import { SnapshotService } from "../snapshots/snapshot.service";

/**
 * Drift detection (Prompt 22 §33–§50). Compares the two most recent
 * IMMUTABLE snapshots per workspace and persists drift events. The
 * intelligence path (§49/§50) is separate from scanning: when stored
 * CVE/EPSS/KEV data moves, affected findings are RE-SCORED with Risk
 * Engine V3 and a RiskDriftEvent is recorded — scanners never rerun
 * for intel movement.
 */
@Injectable()
export class DriftService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly snapshots: SnapshotService,
  ) {}

  private async entryRows(model: "assetSnapshotEntry" | "findingSnapshotEntry", snapshotId: string) {
    return (this.prisma[model] as unknown as { findMany: (args: unknown) => Promise<Record<string, unknown>[]> })
      .findMany({ where: { snapshotId }, take: 10000 });
  }

  /** Run all drift comparisons for a workspace. Idempotent-ish: each
   *  run compares the latest pair; callers invoke it after capturing
   *  a fresh snapshot. Returns counts for observability (§89). */
  async runDrift(workspaceId: string, actor?: { userId: string; organizationId: string }) {
    const assetResult = await this.runAssetDrift(workspaceId, actor);
    const findingResult = await this.runFindingDrift(workspaceId, actor);
    const intelResult = await this.runIntelDrift(workspaceId, actor);
    return { ...assetResult, ...findingResult, ...intelResult };
  }

  async runAssetDrift(workspaceId: string, actor?: { userId: string; organizationId: string }) {
    const snaps = await this.prisma.assetSnapshot.findMany({ where: { workspaceId }, orderBy: { capturedAt: "desc" }, take: 3 });
    const [current, previous, older] = snaps;
    if (!current || !previous) return { assetDriftEvents: 0, surfaceChanges: 0 };
    const [currRows, prevRows, olderRows] = await Promise.all([
      this.entryRows("assetSnapshotEntry", current.id),
      this.entryRows("assetSnapshotEntry", previous.id),
      older ? this.entryRows("assetSnapshotEntry", older.id) : Promise.resolve([]),
    ]);
    const toEntry = (r: Record<string, unknown>): AssetSnapshotEntry => ({
      assetKey: r.assetKey as string, assetId: r.assetId as string | undefined, host: r.host as string,
      type: r.type as string, exposure: r.exposure as string, scopeStatus: r.scopeStatus as string,
      criticality: r.criticality as string, ports: (r.ports as number[]) ?? [], services: (r.services as string[]) ?? [],
      endpointCount: r.endpointCount as number, stateHash: r.stateHash as string,
    });
    const { assetDrift, surfaceChanges } = diffAssetSnapshots({
      previous: prevRows.map(toEntry),
      current: currRows.map(toEntry),
      knownBefore: new Set(olderRows.map((r) => r.assetKey as string)),
    });
    for (const change of surfaceChanges) {
      await this.prisma.attackSurfaceChange.create({
        data: {
          workspaceId, type: change.type, assetKey: change.assetKey, host: change.host,
          priority: change.priority, detail: change.detail,
          fromSnapshotId: previous.id, toSnapshotId: current.id,
        },
      });
    }
    for (const event of assetDrift) {
      await this.prisma.driftEvent.create({
        data: {
          workspaceId, domain: "ASSET", changeType: event.type, entityKey: event.assetKey,
          detail: event.changes.length > 0
            ? event.changes.map((c) => `${c.field}: ${JSON.stringify(c.from)} → ${JSON.stringify(c.to)}`).join("; ")
            : `asset ${event.type.toLowerCase()}`,
          fromValue: event.changes as never, toValue: undefined as never,
        },
      });
    }
    if (actor && (assetDrift.length > 0 || surfaceChanges.length > 0)) {
      await this.audit.record({
        actorId: actor.userId, organizationId: actor.organizationId, workspaceId,
        action: "ASSET_DRIFT_DETECTED", resourceType: "AssetSnapshot", resourceId: current.id,
        metadata: { driftEvents: assetDrift.length, surfaceChanges: surfaceChanges.length },
      });
    }
    return { assetDriftEvents: assetDrift.length, surfaceChanges: surfaceChanges.length };
  }

  async runFindingDrift(workspaceId: string, actor?: { userId: string; organizationId: string }) {
    const snaps = await this.prisma.findingSnapshot.findMany({ where: { workspaceId }, orderBy: { capturedAt: "desc" }, take: 2 });
    const [current, previous] = snaps;
    if (!current || !previous) return { findingDriftEvents: 0 };
    const [currRows, prevRows] = await Promise.all([
      this.entryRows("findingSnapshotEntry", current.id),
      this.entryRows("findingSnapshotEntry", previous.id),
    ]);
    const toEntry = (r: Record<string, unknown>): FindingSnapshotEntry => ({
      findingId: r.findingId as string | undefined, fingerprint: r.fingerprint as string,
      status: r.status as string, lifecycleStatus: r.lifecycleStatus as string, severity: r.severity as string,
      priority: r.priority as string | null, riskScore: r.riskScore as number | null,
      verificationStatus: r.verificationStatus as string, kevListed: r.kevListed as boolean,
      cve: r.cve as string | null, stateHash: r.stateHash as string,
    });
    const events = diffFindingSnapshots({ previous: prevRows.map(toEntry), current: currRows.map(toEntry) });
    for (const event of events) {
      await this.prisma.findingDriftEvent.create({
        data: {
          workspaceId, type: event.type, fingerprint: event.fingerprint, findingId: event.findingId,
          detail: event.detail,
          fromValue: (event.from ?? undefined) as never, toValue: (event.to ?? undefined) as never,
        },
      });
    }
    if (actor && events.length > 0) {
      await this.audit.record({
        actorId: actor.userId, organizationId: actor.organizationId, workspaceId,
        action: "FINDING_DRIFT_DETECTED", resourceType: "FindingSnapshot", resourceId: current.id,
        metadata: { events: events.length },
      });
    }
    return { findingDriftEvents: events.length };
  }

  /**
   * §49/§50: intelligence refresh evaluation over STORED intel rows.
   * The refresh itself (fetching NVD/EPSS/KEV) is performed by the
   * Prompt 11 sync engine when a data source is configured — the
   * production dataset ships empty and no egress fetcher is wired,
   * so scheduled INTEL_SYNC runs honestly record that state. What
   * THIS method does, whenever it runs, is compare current intel
   * against each finding's stored intel snapshot, emit risk drift
   * and recalculate affected scores with Risk Engine V3.
   */
  async runIntelDrift(workspaceId: string, actor?: { userId: string; organizationId: string }) {
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId, duplicateOfId: null, cve: { not: null } } as never,
      take: 5000,
    });
    if (findings.length === 0) return { riskDriftEvents: 0, recalculated: 0 };
    const cves = [...new Set(findings.map((f) => f.cve as string))];
    const [kevRows, epssRows, cveRows] = await Promise.all([
      this.prisma.kevRecord.findMany({ where: { cveId: { in: cves } } }),
      this.prisma.epssRecord.findMany({ where: { cveId: { in: cves } } }),
      this.prisma.cveRecord.findMany({ where: { cveId: { in: cves } } }),
    ]);
    const kevSet = new Set((kevRows as Array<{ cveId: string }>).map((r) => r.cveId));
    const epssByCve = new Map((epssRows as Array<{ cveId: string; score: number }>).map((r) => [r.cveId, r.score]));
    const cvssByCve = new Map((cveRows as Array<{ cveId: string; cvssScore: number | null }>).map((r) => [r.cveId, r.cvssScore]));
    const findingsByCve = new Map<string, string[]>();
    for (const f of findings) findingsByCve.set(f.cve as string, [...(findingsByCve.get(f.cve as string) ?? []), f.id]);

    const previous: IntelView[] = [];
    const current: IntelView[] = [];
    for (const cve of cves) {
      const anyFinding = findings.find((f) => f.cve === cve);
      const snap = (anyFinding?.intelSnapshot ?? null) as { kevListed?: boolean; epssScore?: number; cvssScore?: number } | null;
      previous.push({ cve, kevListed: snap?.kevListed ?? anyFinding?.kevListed ?? false, epssScore: snap?.epssScore ?? anyFinding?.epssScore ?? null, cvssScore: snap?.cvssScore ?? anyFinding?.intelCvssScore ?? null });
      current.push({ cve, kevListed: kevSet.has(cve), epssScore: epssByCve.get(cve) ?? anyFinding?.epssScore ?? null, cvssScore: cvssByCve.get(cve) ?? anyFinding?.intelCvssScore ?? null });
    }
    const events = diffIntelSnapshots({ previous, current, findingsByCve });
    let recalculated = 0;
    const affectedFindingIds = new Set(events.map((e) => e.findingId).filter(Boolean) as string[]);
    for (const event of events) {
      await this.prisma.riskDriftEvent.create({
        data: {
          workspaceId, type: event.type, findingId: event.findingId, cve: event.cve, detail: event.detail,
          fromValue: (event.from ?? undefined) as never, toValue: (event.to ?? undefined) as never,
        },
      });
    }
    // §50: recalculate ONLY the affected findings, from stored data.
    for (const findingId of affectedFindingIds) {
      const finding = findings.find((f) => f.id === findingId);
      if (!finding?.cve) continue;
      const asset = finding.assetId ? await this.prisma.asset.findUnique({ where: { id: finding.assetId } }) : null;
      const result = computeRiskV3({
        severity: finding.severity as never,
        cvssScore: cvssByCve.get(finding.cve) ?? finding.intelCvssScore ?? finding.cvssScore ?? undefined,
        confidence: finding.confidence,
        assetCriticality: asset?.criticality ?? "UNSPECIFIED",
        internetExposed: asset ? asset.scopeStatus === "IN_SCOPE" && !!asset.ip : undefined,
        verificationStatus: finding.verificationStatus,
        enrichment: {
          cveId: finding.cve, kevListed: kevSet.has(finding.cve), linkKeys: [],
          cvss: { scanner: finding.cvssScore ?? undefined, intelligence: cvssByCve.get(finding.cve) ?? undefined, effective: cvssByCve.get(finding.cve) ?? finding.cvssScore ?? undefined },
          ...(epssByCve.has(finding.cve) ? { epss: { cveId: finding.cve, score: epssByCve.get(finding.cve)! } as never } : {}),
        } as never,
        ageDays: Math.max(0, Math.floor((Date.now() - new Date(finding.createdAt).getTime()) / 86400_000)),
        environment: (finding as unknown as { environment?: string }).environment,
        dataSensitivity: (finding as unknown as { dataSensitivity?: string }).dataSensitivity,
      });
      await this.prisma.finding.update({
        where: { id: finding.id },
        data: {
          riskScore: result.score, riskBand: result.band, priority: result.priority,
          kevListed: kevSet.has(finding.cve), epssScore: epssByCve.get(finding.cve) ?? finding.epssScore,
          riskCalcVersion: result.calcVersion,
          intelSnapshot: { kevListed: kevSet.has(finding.cve), epssScore: epssByCve.get(finding.cve) ?? null, cvssScore: cvssByCve.get(finding.cve) ?? null } as never,
        },
      });
      recalculated++;
    }
    if (actor && events.length > 0) {
      await this.audit.record({
        actorId: actor.userId, organizationId: actor.organizationId, workspaceId,
        action: "RISK_DRIFT_DETECTED", resourceType: "Finding", resourceId: [...affectedFindingIds][0] ?? workspaceId,
        metadata: { events: events.length, recalculated },
      });
    }
    return { riskDriftEvents: events.length, recalculated };
  }

  // ---- Read models (§83/§86) ----

  async listDrift(user: RequestUser, workspaceId: string, filters: { domain?: string; type?: string } = {}) {
    requireContinuousPermission(user, "VIEW_SECURITY_DRIFT");
    const where: Record<string, unknown> = { workspaceId };
    if (filters.domain) where.domain = filters.domain;
    const [generic, finding, risk, surface] = await Promise.all([
      this.prisma.driftEvent.findMany({ where: where as never, orderBy: { detectedAt: "desc" }, take: 200 }),
      filters.domain && filters.domain !== "FINDING" ? [] : this.prisma.findingDriftEvent.findMany({ where: { workspaceId, ...(filters.type ? { type: filters.type } : {}) }, orderBy: { detectedAt: "desc" }, take: 200 }),
      filters.domain && filters.domain !== "RISK" ? [] : this.prisma.riskDriftEvent.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 200 }),
      filters.domain && filters.domain !== "ASSET" ? [] : this.prisma.attackSurfaceChange.findMany({ where: { workspaceId, ...(filters.type ? { type: filters.type } : {}) }, orderBy: { detectedAt: "desc" }, take: 200 }),
    ]);
    return { driftEvents: generic, findingDrift: finding, riskDrift: risk, attackSurfaceChanges: surface };
  }

  async listAttackSurfaceChanges(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_SECURITY_DRIFT");
    return this.prisma.attackSurfaceChange.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 200 });
  }

  /** Timeline (§79): chronological merge of drift + surface changes. */
  async timeline(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const [surface, finding, risk, generic, runs] = await Promise.all([
      this.prisma.attackSurfaceChange.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 100 }),
      this.prisma.findingDriftEvent.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 100 }),
      this.prisma.riskDriftEvent.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 100 }),
      this.prisma.driftEvent.findMany({ where: { workspaceId }, orderBy: { detectedAt: "desc" }, take: 100 }),
      this.prisma.scheduleRun.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 }),
    ]);
    const items = [
      ...surface.map((e) => ({ at: e.detectedAt, kind: "ATTACK_SURFACE", type: e.type, detail: e.detail, ref: e.assetKey })),
      ...finding.map((e) => ({ at: e.detectedAt, kind: "FINDING_DRIFT", type: e.type, detail: e.detail, ref: e.fingerprint })),
      ...risk.map((e) => ({ at: e.detectedAt, kind: "RISK_DRIFT", type: e.type, detail: e.detail, ref: e.cve ?? e.findingId ?? "" })),
      ...generic.map((e) => ({ at: e.detectedAt, kind: `DRIFT_${e.domain}`, type: e.changeType, detail: e.detail, ref: e.entityKey })),
      ...runs.map((e) => ({ at: e.createdAt, kind: "SCHEDULE_RUN", type: e.status, detail: e.reason ?? e.reasonCode ?? "", ref: e.scheduleId })),
    ].sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime()).slice(0, 300);
    return { items };
  }
}
