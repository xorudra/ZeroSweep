import { Inject, Injectable } from "@nestjs/common";
import { certificateState } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";

type Row = Record<string, unknown>;

/**
 * EASM dashboard, search and analytics (Prompt 29 §98, §105–§110).
 * Every number is computed from stored EASM rows — an empty program
 * yields an empty dashboard, never synthesized values. Ownership
 * coverage (§109) is defined exactly: candidates with VERIFIED
 * ownership or an assigned owner ÷ ACTIVE external candidates.
 */
@Injectable()
export class EasmAnalyticsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  private async programCandidates(workspaceId: string, programId?: string): Promise<Row[]> {
    const where: Row = { workspaceId };
    if (programId) where.programId = programId;
    return (await this.prisma.easmAssetCandidate.findMany({ where: where as never, take: 5000 })) as Row[];
  }

  async dashboard(user: RequestUser, workspaceId: string, programId?: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const candidates = await this.programCandidates(workspaceId, programId);
    const live = candidates.filter((c) => c.lifecycle !== "DISAPPEARED" && c.lifecycle !== "ARCHIVED");
    const now = Date.now();
    const weekAgo = now - 7 * 86_400_000;
    const certs = (await this.prisma.easmCertificate.findMany({ where: { workspaceId }, take: 2000 })) as Row[];
    const services = (await this.prisma.serviceObservation.findMany({ where: { workspaceId }, take: 5000 })) as Row[];
    const driftWhere: Row = { workspaceId, status: "OPEN" };
    if (programId) driftWhere.programId = programId;
    const recentDrift = await this.prisma.easmDriftEvent.findMany({ where: driftWhere as never, orderBy: { detectedAt: "desc" }, take: 20 });
    const findings = live.some((c) => c.promotedAssetId)
      ? await this.prisma.finding.findMany({
          where: { assetId: { in: live.map((c) => c.promotedAssetId).filter(Boolean) as string[] } }, take: 5000,
        }).catch(() => [] as Row[])
      : [];
    const certHealth = { HEALTHY: 0, EXPIRING: 0, URGENT: 0, EXPIRED: 0 } as Record<string, number>;
    for (const cert of certs) {
      const state = cert.notAfter ? certificateState(new Date(cert.notAfter as string), new Date()) : "HEALTHY";
      certHealth[state] = (certHealth[state] ?? 0) + 1;
    }
    return {
      totalExternalAssets: live.length,
      newAssetsThisWeek: live.filter((c) => new Date(c.firstSeen as string).getTime() >= weekAgo).length,
      unknownAssets: live.filter((c) => c.ownershipStatus === "UNKNOWN").length,
      internetFacingAssets: live.filter((c) => c.exposureState === "INTERNET_EXPOSED").length,
      criticalExposures: live.filter((c) => c.exposureState === "INTERNET_EXPOSED" && (c.criticality === "CRITICAL" || c.criticality === "HIGH")).length,
      kevExposure: (findings as Row[]).filter((f) => f.kev === true || (f.cve as string | null) && (f.severity === "CRITICAL")).length,
      sensitiveServices: services.filter((s) => s.sensitiveClass).length,
      certificateHealth: certHealth,
      recentDrift,
      ownershipCoverage: this.ownershipCoverage(live),
    };
  }

  /** §109 with the denominator stated in the payload. */
  ownershipCoverage(candidates: Row[]) {
    const active = candidates.filter((c) => c.lifecycle === "ACTIVE" || c.lifecycle === "DISCOVERED" || c.lifecycle === "STALE");
    const owned = active.filter((c) => c.ownershipStatus === "VERIFIED" || c.technicalOwner || c.team);
    return {
      owned: owned.length,
      denominator: active.length,
      ratio: active.length === 0 ? null : Number((owned.length / active.length).toFixed(4)),
      definition: "assets with verified ownership or an assigned owner ÷ active external assets",
    };
  }

  /** §107/§108: growth + exposure trends from firstSeen/snapshot rows. */
  async trends(user: RequestUser, workspaceId: string, programId?: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const candidates = await this.programCandidates(workspaceId, programId);
    const now = Date.now();
    const windows = [7, 30, 90].map((days) => {
      const since = now - days * 86_400_000;
      return {
        days,
        newAssets: candidates.filter((c) => new Date(c.firstSeen as string).getTime() >= since).length,
        removedAssets: candidates.filter((c) => c.lifecycle === "DISAPPEARED" && new Date(c.updatedAt as string).getTime() >= since).length,
        unknownAssets: candidates.filter((c) => c.ownershipStatus === "UNKNOWN" && new Date(c.firstSeen as string).getTime() >= since).length,
      };
    });
    const snapshots = await this.prisma.hostExposureSnapshot.findMany({
      where: { workspaceId, ...(programId ? { programId } : {}) }, orderBy: { capturedAt: "desc" }, take: 100,
    });
    return { windows, exposureSnapshots: snapshots };
  }

  /** §103/§110: technology inventory ranked by exposure + findings. */
  async technologies(user: RequestUser, workspaceId: string, programId?: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const candidates = await this.programCandidates(workspaceId, programId);
    const byId = new Map(candidates.map((c) => [c.id as string, c]));
    const observations = (await this.prisma.technologyObservation.findMany({
      where: { workspaceId, candidateId: { in: candidates.map((c) => c.id as string) } }, take: 5000,
    })) as Row[];
    const grouped = new Map<string, { technology: string; versions: Set<string>; assetIds: Set<string>; publicAssets: number; confidence: string }>();
    for (const o of observations) {
      const key = o.normalizedName as string;
      const entry = grouped.get(key) ?? { technology: o.technology as string, versions: new Set<string>(), assetIds: new Set<string>(), publicAssets: 0, confidence: o.confidence as string };
      entry.assetIds.add(o.candidateId as string);
      if (o.version) entry.versions.add(o.version as string);
      if (byId.get(o.candidateId as string)?.exposureState === "INTERNET_EXPOSED") entry.publicAssets++;
      grouped.set(key, entry);
    }
    const items = [...grouped.values()].map((g) => ({
      technology: g.technology, versions: [...g.versions], assetCount: g.assetIds.size,
      publicExposure: g.publicAssets, confidence: g.confidence,
    })).sort((a, b) => b.publicExposure - a.publicExposure || b.assetCount - a.assetCount);
    return { items, total: items.length };
  }

  /** §104: certificate inventory. */
  async certificates(user: RequestUser, workspaceId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const certs = (await this.prisma.easmCertificate.findMany({ where: { workspaceId }, orderBy: { notAfter: "asc" }, take: 1000 })) as Row[];
    const observations = (await this.prisma.easmCertificateObservation.findMany({ where: { workspaceId }, take: 5000 })) as Row[];
    const items = certs.map((c) => ({
      ...c,
      computedState: c.notAfter ? certificateState(new Date(c.notAfter as string), new Date()) : c.state,
      hosts: [...new Set(observations.filter((o) => o.certificateId === c.id).map((o) => o.host as string))],
      sanCount: Array.isArray(c.sans) ? (c.sans as unknown[]).length : 0,
    }));
    return { items, total: items.length };
  }

  /**
   * §105: EASM search over the documented query syntax
   * (ownership:, internet_exposed:, technology:, service:,
   * certificate_status:, new_asset:) — parsed into governed filters,
   * never string-interpolated into a query.
   */
  async search(user: RequestUser, workspaceId: string, rawQuery: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const filters: Row = { workspaceId };
    let technology: string | null = null;
    let servicePort: number | null = null;
    let certStatus: string | null = null;
    for (const token of rawQuery.split(/\s+/).filter(Boolean)) {
      const [key, ...rest] = token.split(":");
      const value = rest.join(":");
      switch (key) {
        case "ownership": filters.ownershipStatus = value.toUpperCase(); break;
        case "internet_exposed": if (value === "true") filters.exposureState = "INTERNET_EXPOSED"; break;
        case "technology": technology = value.toLowerCase(); break;
        case "service": servicePort = /^\d+$/.test(value) ? Number(value) : null; break;
        case "certificate_status": certStatus = value.toUpperCase(); break;
        case "new_asset": if (value === "true") filters.lifecycle = "DISCOVERED"; break;
        default: break; // free text is matched against normalizedValue below
      }
    }
    let items = (await this.prisma.easmAssetCandidate.findMany({ where: filters as never, take: 500 })) as Row[];
    const freeText = rawQuery.split(/\s+/).filter((t) => !t.includes(":")).join(" ").toLowerCase();
    if (freeText) items = items.filter((c) => (c.normalizedValue as string).includes(freeText));
    if (technology) {
      const techObs = (await this.prisma.technologyObservation.findMany({ where: { workspaceId, normalizedName: technology }, take: 5000 })) as Row[];
      const ids = new Set(techObs.map((o) => o.candidateId as string));
      items = items.filter((c) => ids.has(c.id as string));
    }
    if (servicePort !== null) {
      const svcObs = (await this.prisma.serviceObservation.findMany({ where: { workspaceId, port: servicePort }, take: 5000 })) as Row[];
      const ids = new Set(svcObs.map((o) => o.candidateId as string));
      items = items.filter((c) => ids.has(c.id as string));
    }
    if (certStatus) {
      const certObs = (await this.prisma.easmCertificateObservation.findMany({ where: { workspaceId }, take: 5000 })) as Row[];
      const certs = (await this.prisma.easmCertificate.findMany({ where: { workspaceId }, take: 2000 })) as Row[];
      const matchingCertIds = new Set(certs.filter((c) => (c.notAfter ? certificateState(new Date(c.notAfter as string), new Date()) : c.state) === certStatus).map((c) => c.id as string));
      const ids = new Set(certObs.filter((o) => matchingCertIds.has(o.certificateId as string)).map((o) => o.candidateId as string));
      items = items.filter((c) => ids.has(c.id as string));
    }
    return { items, total: items.length, appliedFilters: { ...filters, technology, servicePort, certStatus } };
  }
}
