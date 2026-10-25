import { Inject, Injectable } from "@nestjs/common";
import {
  assetKeyOf, buildAssetSnapshotEntry, buildFindingSnapshotEntry, buildPostureSnapshot,
  canonicalHash, cidrContains,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireContinuousPermission } from "../permissions";

const PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"];
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Evidence-based exposure (§36): a stored public IP means
 * INTERNET_FACING; a stored private/loopback/link-local IP means
 * PRIVATE; anything else is UNKNOWN — exposure is never guessed from
 * a hostname alone.
 */
export function deriveExposure(ip: string | null | undefined): string {
  if (!ip || !IPV4_RE.test(ip)) return "UNKNOWN";
  if (PRIVATE_CIDRS.some((c) => cidrContains(c, ip))) return "PRIVATE";
  return "INTERNET_FACING";
}

const MAX_ASSETS = 5000;
const MAX_FINDINGS = 10000;

/**
 * Snapshot capture (Prompt 22 §29–§32). Snapshots are immutable:
 * this service only ever CREATES rows — there is deliberately no
 * update or delete path, and posture history reads these rows
 * instead of recomputing from current state.
 */
@Injectable()
export class SnapshotService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async captureSnapshots(workspaceId: string, source: string, actor?: { userId: string; organizationId: string }) {
    const [posture, assetSnapshot, findingSnapshot] = await Promise.all([
      this.capturePosture(workspaceId, source),
      this.captureAssets(workspaceId, source),
      this.captureFindings(workspaceId, source),
    ]);
    if (actor) {
      await this.audit.record({
        actorId: actor.userId, organizationId: actor.organizationId, workspaceId,
        action: "POSTURE_SNAPSHOT_CREATED", resourceType: "SecurityPostureSnapshot", resourceId: posture.id,
        metadata: { assetSnapshotId: assetSnapshot.id, findingSnapshotId: findingSnapshot.id, source },
      });
    }
    return { posture, assetSnapshot, findingSnapshot };
  }

  async capturePosture(workspaceId: string, source: string) {
    const now = new Date();
    const canonical = { workspaceId, duplicateOfId: null };
    const [assetCount, findings, bySeverity, byStatus, riskRows] = await Promise.all([
      this.prisma.asset.count({ where: { workspaceId } }),
      this.prisma.finding.count({ where: canonical as never }),
      this.prisma.finding.groupBy({ by: ["severity"], where: canonical as never, _count: true }),
      this.prisma.finding.groupBy({ by: ["lifecycleStatus"], where: canonical as never, _count: true }),
      this.prisma.finding.findMany({ where: canonical as never, select: { riskScore: true, kevListed: true, verificationStatus: true, dueAt: true, lifecycleStatus: true, assetId: true }, take: MAX_FINDINGS }),
    ]);
    const findingsBySeverity: Record<string, number> = {};
    for (const r of bySeverity as Array<{ severity: string; _count: number }>) findingsBySeverity[r.severity] = r._count;
    const findingsByStatus: Record<string, number> = {};
    for (const r of byStatus as Array<{ lifecycleStatus: string; _count: number }>) findingsByStatus[r.lifecycleStatus] = r._count;
    const resolved = new Set(["RESOLVED", "CLOSED", "FIXED", "REMEDIATED", "FALSE_POSITIVE"]);
    const slaOverdue = riskRows.filter((f) => f.dueAt && f.dueAt < now && !resolved.has(f.lifecycleStatus)).length;
    const dueSoonBefore = new Date(now.getTime() + 7 * 24 * 3600_000);
    const slaDueSoon = riskRows.filter((f) => f.dueAt && f.dueAt >= now && f.dueAt < dueSoonBefore && !resolved.has(f.lifecycleStatus)).length;
    const assetsWithFindings = new Set(riskRows.map((f) => f.assetId).filter(Boolean));
    const data = buildPostureSnapshot({
      aggregates: {
        assetCount, findingCount: findings,
        findingsBySeverity, findingsByStatus,
        kevCount: riskRows.filter((f) => f.kevListed).length,
        verifiedFindings: riskRows.filter((f) => f.verificationStatus === "CONFIRMED").length,
        slaOverdue, slaDueSoon,
        coverage: assetCount === 0 ? null : Math.round((assetsWithFindings.size / assetCount) * 1000) / 1000,
      },
      findingRiskScores: riskRows.map((f) => f.riskScore).filter((s): s is number => typeof s === "number"),
    });
    return this.prisma.securityPostureSnapshot.create({
      data: {
        workspaceId, source, assetCount: data.assetCount, findingCount: data.findingCount,
        findingsBySeverity: data.findingsBySeverity as never, findingsByStatus: data.findingsByStatus as never,
        kevCount: data.kevCount, verifiedFindings: data.verifiedFindings,
        slaOverdue: data.slaOverdue, slaDueSoon: data.slaDueSoon,
        coverage: data.coverage, riskScore: data.riskScore, contentHash: data.contentHash,
      },
    });
  }

  async captureAssets(workspaceId: string, source: string) {
    const assets = await this.prisma.asset.findMany({
      where: { workspaceId },
      include: { services: true, endpoints: true },
      take: MAX_ASSETS,
      orderBy: { createdAt: "asc" },
    });
    const entries = assets.map((a) => buildAssetSnapshotEntry({
      assetKey: assetKeyOf({ targetId: a.targetId, host: a.host, type: a.type }),
      assetId: a.id, host: a.host, type: a.type,
      exposure: deriveExposure(a.ip),
      scopeStatus: a.scopeStatus, criticality: a.criticality,
      ports: (a.services ?? []).map((s: { port: number }) => s.port),
      services: (a.services ?? []).map((s: { name: string | null; product: string | null; port: number }) => s.name ?? s.product ?? `port-${s.port}`),
      endpointCount: (a.endpoints ?? []).length,
    }));
    const snapshot = await this.prisma.assetSnapshot.create({
      data: { workspaceId, source, entryCount: entries.length, contentHash: canonicalHash(entries.map((e) => e.stateHash)) },
    });
    if (entries.length > 0) {
      await this.prisma.assetSnapshotEntry.createMany({
        data: entries.map((e) => ({
          snapshotId: snapshot.id, workspaceId, assetKey: e.assetKey, assetId: e.assetId, host: e.host, type: e.type,
          exposure: e.exposure, scopeStatus: e.scopeStatus, criticality: e.criticality,
          ports: e.ports as never, services: e.services as never, endpointCount: e.endpointCount, stateHash: e.stateHash,
        })),
      });
    }
    return snapshot;
  }

  async captureFindings(workspaceId: string, source: string) {
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId, duplicateOfId: null } as never,
      take: MAX_FINDINGS,
      orderBy: { createdAt: "asc" },
    });
    const entries = findings.map((f) => buildFindingSnapshotEntry({
      findingId: f.id, fingerprint: f.fingerprint ?? f.id,
      status: f.status, lifecycleStatus: f.lifecycleStatus, severity: f.severity,
      priority: f.priority, riskScore: f.riskScore, verificationStatus: f.verificationStatus,
      kevListed: f.kevListed, cve: f.cve,
    }));
    const snapshot = await this.prisma.findingSnapshot.create({
      data: { workspaceId, source, entryCount: entries.length, contentHash: canonicalHash(entries.map((e) => e.stateHash)) },
    });
    if (entries.length > 0) {
      await this.prisma.findingSnapshotEntry.createMany({
        data: entries.map((e) => ({
          snapshotId: snapshot.id, workspaceId, findingId: e.findingId, fingerprint: e.fingerprint,
          status: e.status, lifecycleStatus: e.lifecycleStatus, severity: e.severity, priority: e.priority,
          riskScore: e.riskScore, verificationStatus: e.verificationStatus, kevListed: e.kevListed,
          cve: e.cve, stateHash: e.stateHash,
        })),
      });
    }
    return snapshot;
  }

  async listPosture(user: RequestUser, workspaceId: string, take = 100) {
    requireContinuousPermission(user, "VIEW_POSTURE_HISTORY");
    return this.prisma.securityPostureSnapshot.findMany({
      where: { workspaceId }, orderBy: { capturedAt: "desc" }, take: Math.min(take, 500),
    });
  }

  async latestSnapshots(workspaceId: string) {
    const [posture, asset, finding] = await Promise.all([
      this.prisma.securityPostureSnapshot.findFirst({ where: { workspaceId }, orderBy: { capturedAt: "desc" } }),
      this.prisma.assetSnapshot.findFirst({ where: { workspaceId }, orderBy: { capturedAt: "desc" } }),
      this.prisma.findingSnapshot.findFirst({ where: { workspaceId }, orderBy: { capturedAt: "desc" } }),
    ]);
    return { posture, asset, finding };
  }
}
