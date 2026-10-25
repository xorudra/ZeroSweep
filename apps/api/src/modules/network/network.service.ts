import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { networkSummary, type NormalizedService } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";

/**
 * Network inventory API (Prompt 10 §66–§73). READ-ONLY views over what
 * authorized network scans discovered: networks, hosts, ports/services
 * with provenance, and packet-capture metadata. Every query is
 * workspace-scoped through the caller's organization (§83 tenant
 * isolation) — a foreign id is a 404, never a leak. Counts are computed
 * from real rows only: the summary the GUI renders is exactly the
 * merged inventory (§72), never an estimate.
 */
@Injectable()
export class NetworkService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  /** §66/§70: networks group hosts by their canonical network; the map
   *  is built ONLY from these recorded relationships — unknown
   *  relationships are never guessed (§70). */
  async listNetworks(user: RequestUser) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const assets = await this.prisma.asset.findMany({
      where: { workspaceId: workspace.id },
      include: { services: true, _count: { select: { findings: true } } },
      take: 5000,
    });
    const groups = new Map<string, { network: string; hosts: number; openPorts: number; services: number; findings: number }>();
    for (const a of assets as unknown as Array<Record<string, unknown>>) {
      const network = (a.network as string | null) ?? "UNGROUPED";
      const g = groups.get(network) ?? { network, hosts: 0, openPorts: 0, services: 0, findings: 0 };
      g.hosts++;
      const services = (a.services as Array<{ state?: string }>) ?? [];
      g.services += services.length;
      g.openPorts += services.filter((s) => (s.state ?? "OPEN") === "OPEN").length;
      g.findings += ((a._count as { findings?: number } | undefined)?.findings ?? 0);
      groups.set(network, g);
    }
    return { networks: [...groups.values()].sort((x, y) => x.network.localeCompare(y.network)) };
  }

  async listHosts(user: RequestUser, query: { page: number; pageSize: number; search?: string; network?: string }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const where: Record<string, unknown> = { workspaceId: workspace.id };
    if (query.network) where.network = query.network;
    if (query.search) where.host = { contains: query.search };
    const [total, rows] = await Promise.all([
      this.prisma.asset.count({ where: where as never }),
      this.prisma.asset.findMany({
        where: where as never,
        include: { services: true, technologies: true, _count: { select: { findings: true, endpoints: true } } },
        orderBy: { host: "asc" },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
    ]);
    const items = (rows as unknown as Array<Record<string, unknown>>).map((a) => this.hostSummary(a));
    return { items, total, page: query.page, pageSize: query.pageSize };
  }

  private hostSummary(a: Record<string, unknown>) {
    const services = (a.services as Array<{ state?: string; port: number }>) ?? [];
    return {
      id: a.id, host: a.host, ip: a.ip ?? null, type: a.type,
      scopeStatus: a.scopeStatus, sources: a.sources ?? [],
      osHint: a.osHint ?? null, osConfidence: a.osConfidence ?? null,
      network: a.network ?? null, criticality: a.criticality ?? "UNSPECIFIED",
      openPorts: services.filter((s) => (s.state ?? "OPEN") === "OPEN").length,
      services: services.length,
      findings: ((a._count as { findings?: number } | undefined)?.findings ?? 0),
      endpoints: ((a._count as { endpoints?: number } | undefined)?.endpoints ?? 0),
      firstSeen: a.firstSeen, lastSeen: a.lastSeen,
    };
  }

  private async loadHost(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const asset = await this.prisma.asset.findFirst({
      where: { id, workspaceId: workspace.id },
      include: {
        services: { orderBy: { port: "asc" } },
        technologies: true,
        findings: { orderBy: { createdAt: "desc" }, take: 100 },
        endpoints: { take: 100 },
        packetCaptures: { orderBy: { createdAt: "desc" }, take: 50 },
      },
    });
    if (!asset) throw new NotFoundException("Host not found");
    return asset as unknown as Record<string, unknown>;
  }

  async getHost(user: RequestUser, id: string) {
    const a = await this.loadHost(user, id);
    const services = (a.services as Array<{ state?: string }>) ?? [];
    return {
      ...this.hostSummary(a),
      servicesDetail: a.services,
      technologies: a.technologies ?? [],
      findingsDetail: a.findings ?? [],
      endpoints: a.endpoints ?? [],
      packetCaptures: ((a.packetCaptures as Array<Record<string, unknown>>) ?? []).map((c) => this.captureSummary(c)),
      openPorts: services.filter((s) => (s.state ?? "OPEN") === "OPEN").length,
    };
  }

  async listHostServices(user: RequestUser, id: string) {
    const a = await this.loadHost(user, id);
    return { host: a.host, services: a.services ?? [] };
  }

  /** §73: per-scan views key on the assets the scan discovered +
   *  the findings it produced. The summary is the §72 shape computed
   *  from the merged inventory rows. */
  private async loadScan(user: RequestUser, scanId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    return { workspace, scan: scan as unknown as Record<string, unknown> };
  }

  async scanHosts(user: RequestUser, scanId: string) {
    const { workspace } = await this.loadScan(user, scanId);
    const rows = await this.prisma.asset.findMany({
      where: { workspaceId: workspace.id, discoveredByScanId: scanId },
      include: { services: true, technologies: true, _count: { select: { findings: true, endpoints: true } } },
      orderBy: { host: "asc" },
      take: 2000,
    });
    return { hosts: (rows as unknown as Array<Record<string, unknown>>).map((a) => this.hostSummary(a)) };
  }

  async scanNetworkSummary(user: RequestUser, scanId: string) {
    const { workspace } = await this.loadScan(user, scanId);
    const [assets, findingsCount, chunks, captures] = await Promise.all([
      this.prisma.asset.findMany({
        where: { workspaceId: workspace.id, discoveredByScanId: scanId },
        include: { services: true },
        take: 5000,
      }),
      this.prisma.finding.count({ where: { scanId } }),
      this.prisma.networkScanChunk.findMany({ where: { scanId }, orderBy: { chunkId: "asc" }, take: 500 }),
      this.prisma.packetCaptureArtifact.count({ where: { scanId } }),
    ]);
    const hostByAssetId = new Map<string, string>();
    const services: NormalizedService[] = [];
    for (const a of assets as unknown as Array<Record<string, unknown>>) {
      hostByAssetId.set(a.id as string, a.host as string);
      for (const s of (a.services as Array<Record<string, unknown>>) ?? []) {
        services.push({
          host: a.host as string, port: s.port as number, protocol: (s.protocol as string) ?? "tcp",
          name: (s.name as string) ?? undefined, state: (s.state as NormalizedService["state"]) ?? "OPEN",
          tls: (s.tls as boolean) ?? undefined, sources: (s.sources as string[]) ?? [],
        });
      }
    }
    const summary = networkSummary(services, (assets as unknown[]).length, findingsCount, 0);
    return {
      scanId,
      ...summary,
      chunks: (chunks as unknown as Array<Record<string, unknown>>).map((c) => ({
        chunkId: c.chunkId, rangeStart: c.rangeStart, rangeEnd: c.rangeEnd,
        hostCount: c.hostCount, status: c.status,
      })),
      packetCaptures: captures,
    };
  }

  private captureSummary(c: Record<string, unknown>) {
    return {
      id: c.id, format: c.format, source: c.source, storageKey: c.storageKey,
      sha256: c.sha256 ?? null, sizeBytes: c.sizeBytes ?? null,
      durationSeconds: c.durationSeconds ?? null, interfaceName: c.interfaceName ?? null,
      packetCount: c.packetCount ?? null, scanId: c.scanId ?? null,
      retentionUntil: c.retentionUntil ?? null, createdAt: c.createdAt,
    };
  }

  /** §43/§83: capture metadata is tenant-isolated like everything else. */
  async listPacketCaptures(user: RequestUser, query: { scanId?: string }) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.packetCaptureArtifact.findMany({
      where: { workspaceId: workspace.id, ...(query.scanId ? { scanId: query.scanId } : {}) },
      orderBy: { createdAt: "desc" },
      take: 200,
    });
    return { captures: (rows as unknown as Array<Record<string, unknown>>).map((c) => this.captureSummary(c)) };
  }

  /** §47: raw capture access returns the storage REFERENCE + integrity
   *  data after the caller has been authorized and audited by the
   *  controller — packet bytes never flow through this API. */
  async loadCaptureForRawAccess(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const capture = await this.prisma.packetCaptureArtifact.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!capture) throw new NotFoundException("Packet capture not found");
    return { workspace, capture: capture as unknown as Record<string, unknown> };
  }
}
