import { Inject, Injectable } from "@nestjs/common";
import { groupCount, sha256Hex, topN } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { deriveExposure } from "../../continuous-security/snapshots/snapshot.service";
import { RESOLVED_LIFECYCLES } from "../helpers";

/**
 * Attack Surface Intelligence (Prompt 27 §51–§60).
 *
 * Correlates assets, services, technologies, findings and exposure
 * from REAL inventory. Unknown/shadow assets are SIGNALS with
 * controlled evidence — never maliciousness verdicts (§55). Growth
 * is computed between recorded snapshots; with fewer than two
 * snapshots the honest answer is the current state plus an empty
 * series.
 */
@Injectable()
export class AttackSurfaceService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async captureSnapshot(workspaceId: string) {
    const current = await this.computeCurrent(workspaceId);
    const previous = await this.prisma.exposureSnapshot.findFirst({
      where: { workspaceId }, orderBy: { capturedAt: "desc" },
    });
    const prevServices = (previous as unknown as { _services?: string[] } | null)?._services;
    void prevServices;
    const prevKeys = previous ? await this.serviceKeysBefore(workspaceId, previous.capturedAt) : null;
    const newServices = prevKeys ? current.serviceKeys.filter((k) => !prevKeys.includes(k)).length : 0;
    const removedServices = prevKeys ? prevKeys.filter((k) => !current.serviceKeys.includes(k)).length : 0;
    const contentHash = sha256Hex(JSON.stringify({
      assets: current.internetFacingAssets, services: current.serviceKeys, critical: current.criticalFindings,
    }));
    const row = await this.prisma.exposureSnapshot.create({
      data: {
        workspaceId, internetFacingAssets: current.internetFacingAssets, totalAssets: current.totalAssets,
        openServices: current.serviceKeys.length, newServices, removedServices,
        highRiskTechnologies: current.highRiskTechnologies, criticalFindings: current.criticalFindings,
        kevFindings: current.kevFindings, unknownAssets: current.unknownAssets, contentHash,
      },
    });
    await this.detectShadowSignals(workspaceId, current.assets);
    return { ...row, serviceKeys: current.serviceKeys };
  }

  private async serviceKeysBefore(workspaceId: string, at: Date): Promise<string[] | null> {
    const snapshot = await this.prisma.assetSnapshot.findFirst({
      where: { workspaceId, capturedAt: { lte: at } } as never, orderBy: { capturedAt: "desc" },
    });
    if (!snapshot) return null;
    const entries = await this.prisma.assetSnapshotEntry.findMany({ where: { snapshotId: snapshot.id }, take: 10_000 });
    const keys: string[] = [];
    for (const e of entries) {
      for (const p of (e.ports as Array<{ port?: number }>) ?? []) keys.push(`${e.host}:${p.port}`);
    }
    return keys;
  }

  private async computeCurrent(workspaceId: string) {
    const [assets, services, findings, techs] = await Promise.all([
      this.prisma.asset.findMany({ where: { workspaceId }, take: 10_000 }),
      this.prisma.service.findMany({ take: 20_000 }),
      this.prisma.finding.findMany({ where: { workspaceId }, take: 10_000 }),
      this.prisma.technology.findMany({ take: 20_000 }),
    ]);
    const assetIds = new Set(assets.map((a) => a.id));
    const scopedServices = services.filter((s) => assetIds.has(s.assetId));
    const scopedTechs = techs.filter((t) => assetIds.has(t.assetId));
    const open = findings.filter((f) => !RESOLVED_LIFECYCLES.has(f.lifecycleStatus));
    const riskyTechNames = new Set(
      open.filter((f) => f.assetId).map((f) => f.assetId),
    );
    return {
      assets,
      totalAssets: assets.length,
      internetFacingAssets: assets.filter((a) => deriveExposure(a.ip) === "INTERNET_FACING").length,
      serviceKeys: scopedServices.filter((s) => s.state === "OPEN").map((s) => `${s.assetId}:${s.port}/${s.protocol}`),
      highRiskTechnologies: scopedTechs.filter((t) => riskyTechNames.has(t.assetId)).length,
      criticalFindings: open.filter((f) => f.severity === "CRITICAL").length,
      kevFindings: open.filter((f) => f.kevListed).length,
      unknownAssets: assets.filter((a) => a.criticality === "UNSPECIFIED" || a.scopeStatus !== "IN_SCOPE").length,
    };
  }

  /** §53: growth between recorded exposure snapshots. */
  async growth(workspaceId: string) {
    const snapshots = await this.prisma.exposureSnapshot.findMany({
      where: { workspaceId }, orderBy: { capturedAt: "asc" }, take: 500,
    });
    if (snapshots.length < 2) {
      return {
        series: snapshots.map((s) => ({ capturedAt: s.capturedAt, totalAssets: s.totalAssets, internetFacingAssets: s.internetFacingAssets })),
        newAssets: null, removedAssets: null, netGrowth: null,
        note: snapshots.length === 0
          ? "No exposure snapshots recorded yet — growth requires at least two captures."
          : "Only one exposure snapshot recorded — growth requires at least two captures.",
      };
    }
    const first = snapshots[0]!; const last = snapshots[snapshots.length - 1]!;
    return {
      series: snapshots.map((s) => ({ capturedAt: s.capturedAt, totalAssets: s.totalAssets, internetFacingAssets: s.internetFacingAssets, openServices: s.openServices })),
      newAssets: Math.max(0, last.totalAssets - first.totalAssets),
      removedAssets: null,
      netGrowth: last.totalAssets - first.totalAssets,
      newExposedServices: snapshots.reduce((sum, s) => sum + s.newServices, 0),
      note: "Derived from recorded ExposureSnapshot captures; removed-asset counts require per-asset snapshot diffing and are reported by the continuous-security drift engine.",
    };
  }

  /** §54/§55: unknown-asset analytics + shadow signals (evidence, not verdicts). */
  private async detectShadowSignals(workspaceId: string, assets: Array<{ id: string; host: string; ip: string | null; criticality: string; scopeStatus: string }>) {
    for (const asset of assets) {
      const signalType = asset.scopeStatus === "OUT_OF_SCOPE" && deriveExposure(asset.ip) === "INTERNET_FACING"
        ? "UNKNOWN_PUBLIC_HOST"
        : asset.criticality === "UNSPECIFIED" && deriveExposure(asset.ip) === "INTERNET_FACING"
          ? "UNEXPECTED_SUBDOMAIN"
          : null;
      if (!signalType) continue;
      const existing = await this.prisma.shadowAssetSignal.findFirst({
        where: { workspaceId, assetId: asset.id, signalType, status: "OPEN" },
      });
      if (existing) continue;
      await this.prisma.shadowAssetSignal.create({
        data: {
          workspaceId, assetId: asset.id, host: asset.host, signalType,
          evidence: { exposure: deriveExposure(asset.ip), scopeStatus: asset.scopeStatus, criticality: asset.criticality } as never,
        },
      });
    }
  }

  async dashboard(workspaceId: string) {
    const current = await this.computeCurrent(workspaceId);
    const [services, techs, findings, snapshots, signals] = await Promise.all([
      this.prisma.service.findMany({ take: 20_000 }),
      this.prisma.technology.findMany({ take: 20_000 }),
      this.prisma.finding.findMany({ where: { workspaceId }, take: 10_000 }),
      this.prisma.exposureSnapshot.findMany({ where: { workspaceId }, orderBy: { capturedAt: "desc" }, take: 30 }),
      this.prisma.shadowAssetSignal.findMany({ where: { workspaceId, status: "OPEN" }, take: 500 }),
    ]);
    const assetIds = new Set(current.assets.map((a) => a.id));
    const assetById = new Map(current.assets.map((a) => [a.id, a]));
    const scopedServices = services.filter((s) => assetIds.has(s.assetId));
    const scopedTechs = techs.filter((t) => assetIds.has(t.assetId));
    const open = findings.filter((f) => !RESOLVED_LIFECYCLES.has(f.lifecycleStatus));
    // §59/§60: certificate analytics derive from TLS-bearing services
    // and certificate-class findings — where no certificate inventory
    // exists the honest output is the TLS-service count + findings.
    const certFindings = findings.filter((f) => /cert|tls|ssl/i.test(`${f.title} ${f.vulnClass ?? ""} ${f.cwe ?? ""}`));
    return {
      sources: ["Asset", "Service", "Technology", "Finding", "ExposureSnapshot", "ShadowAssetSignal"],
      internetFacingAssets: current.internetFacingAssets,
      totalAssets: current.totalAssets,
      newAssets: snapshots.length > 1 ? Math.max(0, current.totalAssets - snapshots[snapshots.length - 1]!.totalAssets) : null,
      unknownAssets: current.unknownAssets,
      shadowSignals: signals.map((s) => ({ id: s.id, host: s.host, signalType: s.signalType, detectedAt: s.detectedAt, note: "Signal from controlled evidence — not a maliciousness verdict (§55)." })),
      services: {
        open: scopedServices.filter((s) => s.state === "OPEN").length,
        byPort: topN(scopedServices, (s) => String(s.port), 15),
        byProduct: topN(scopedServices, (s) => s.product, 10),
        internetExposed: scopedServices.filter((s) => deriveExposure(assetById.get(s.assetId)?.ip) === "INTERNET_FACING").length,
      },
      technologies: {
        distribution: topN(scopedTechs, (t) => t.name, 15),
        withVersions: scopedTechs.filter((t) => t.version).length,
        onInternetFacingAssets: scopedTechs.filter((t) => deriveExposure(assetById.get(t.assetId)?.ip) === "INTERNET_FACING").length,
        criticalFindingsByTechnology: groupCount(
          open.filter((f) => f.assetId),
          (f) => scopedTechs.find((t) => t.assetId === f.assetId)?.name ?? null,
        ).slice(0, 10),
      },
      certificates: {
        tlsServices: scopedServices.filter((s) => s.tls).length,
        certificateFindings: certFindings.length,
        expiringFindings: certFindings.filter((f) => /expir/i.test(f.title)).map((f) => ({ id: f.id, title: f.title, severity: f.severity })),
        note: "Certificate expiry windows (30/14/7d) derive from certificate findings where inventory exists; no certificate inventory table exists in the operational schema.",
      },
      criticalExposure: current.criticalFindings,
      kevExposure: current.kevFindings,
      growth: await this.growth(workspaceId),
    };
  }
}
