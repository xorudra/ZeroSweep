import { NotFoundException } from "@nestjs/common";
import { NetworkService } from "./network.service";

/**
 * Prompt 10 §73/§83: the network inventory API is tenant-isolated
 * (foreign hosts/scans/captures are 404s), the per-scan summary counts
 * the merged inventory only, and capture metadata never exposes bytes.
 */

const user = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

const WORKSPACES = [
  { id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) },
  { id: "ws-2", organizationId: "org-2", deletedAt: null, createdAt: new Date(0) },
];

const SERVICES = [
  { id: "s-1", assetId: "h-1", port: 23, protocol: "tcp", name: "telnet", product: "Linux telnetd", version: null, state: "OPEN", cpe: null, banner: null, tls: null, confidence: 1, sources: ["nmap"] },
  { id: "s-2", assetId: "h-1", port: 443, protocol: "tcp", name: "https", product: "nginx", version: "1.25.3", state: "OPEN", cpe: "cpe:/a:nginx:nginx:1.25.3", banner: null, tls: true, confidence: 1, sources: ["nmap", "naabu"] },
  { id: "s-3", assetId: "h-1", port: 8080, protocol: "tcp", name: "http-proxy", product: null, version: null, state: "CLOSED", cpe: null, banner: null, tls: null, confidence: 0.3, sources: ["nmap"] },
];

const ASSETS = [
  {
    id: "h-1", workspaceId: "ws-1", host: "192.0.2.10", ip: "192.0.2.10", type: "HOST", scopeStatus: "IN_SCOPE",
    sources: ["nmap", "naabu"], osHint: "Linux 5.15", osConfidence: 0.96, network: "192.0.2.0/24",
    criticality: "UNSPECIFIED", discoveredByScanId: "scan-1",
    services: SERVICES, technologies: [], findings: [], endpoints: [], packetCaptures: [],
    _count: { findings: 2, endpoints: 0 }, firstSeen: new Date(0), lastSeen: new Date(0),
  },
  {
    id: "h-2", workspaceId: "ws-2", host: "198.51.100.7", ip: "198.51.100.7", type: "HOST", scopeStatus: "IN_SCOPE",
    sources: ["nmap"], osHint: null, osConfidence: null, network: "198.51.100.0/24",
    criticality: "UNSPECIFIED", discoveredByScanId: "scan-9",
    services: [], technologies: [], findings: [], endpoints: [], packetCaptures: [],
    _count: { findings: 0, endpoints: 0 }, firstSeen: new Date(0), lastSeen: new Date(0),
  },
];

const CAPTURES = [
  { id: "cap-1", workspaceId: "ws-1", scanId: "scan-1", format: "PCAP", source: "IMPORT", storageKey: "scans/scan-1/imports/cap-1.pcap", sha256: "a".repeat(64), sizeBytes: 2048, durationSeconds: null, interfaceName: null, packetCount: 120, retentionUntil: null, createdAt: new Date(0) },
  { id: "cap-2", workspaceId: "ws-2", scanId: "scan-9", format: "PCAPNG", source: "tcpdump", storageKey: "scans/scan-9/x/capture.pcap", sha256: null, sizeBytes: 10, durationSeconds: 60, interfaceName: "eth0", packetCount: 5, retentionUntil: null, createdAt: new Date(0) },
];

function matchWhere(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (v === undefined) continue;
    if (k === "OR") continue;
    if (typeof v === "object" && v !== null && "contains" in (v as Record<string, unknown>)) {
      if (!String(row[k] ?? "").includes((v as { contains: string }).contains)) return false;
      continue;
    }
    if (row[k] !== v) return false;
  }
  return true;
}

function fakePrisma() {
  const assetDelegate = {
    findMany: async (args: { where?: Record<string, unknown>; skip?: number; take?: number }) => {
      let rows = ASSETS.filter((a) => matchWhere(a as unknown as Record<string, unknown>, args.where ?? {}));
      if (args.skip) rows = rows.slice(args.skip);
      if (args.take) rows = rows.slice(0, args.take);
      return rows;
    },
    findFirst: async (args: { where?: Record<string, unknown> }) =>
      ASSETS.find((a) => matchWhere(a as unknown as Record<string, unknown>, args.where ?? {})) ?? null,
    count: async (args: { where?: Record<string, unknown> }) =>
      ASSETS.filter((a) => matchWhere(a as unknown as Record<string, unknown>, args.where ?? {})).length,
  };
  return {
    workspace: {
      findFirst: async (args: { where: Record<string, unknown> }) =>
        WORKSPACES.find((w) => matchWhere(w as unknown as Record<string, unknown>, args.where)) ?? null,
    },
    asset: assetDelegate,
    scan: {
      findFirst: async (args: { where: Record<string, unknown> }) =>
        [{ id: "scan-1", workspaceId: "ws-1" }, { id: "scan-9", workspaceId: "ws-2" }]
          .find((s) => matchWhere(s as unknown as Record<string, unknown>, args.where)) ?? null,
    },
    finding: { count: async () => 2 },
    networkScanChunk: {
      findMany: async () => [{ chunkId: "chunk-0", rangeStart: "192.0.2.1", rangeEnd: "192.0.2.254", hostCount: 254, status: "PENDING" }],
    },
    packetCaptureArtifact: {
      findMany: async (args: { where?: Record<string, unknown> }) =>
        CAPTURES.filter((c) => matchWhere(c as unknown as Record<string, unknown>, args.where ?? {})),
      findFirst: async (args: { where: Record<string, unknown> }) =>
        CAPTURES.find((c) => matchWhere(c as unknown as Record<string, unknown>, args.where)) ?? null,
      count: async () => 1,
    },
  };
}

function makeService() {
  return new NetworkService(fakePrisma() as never);
}

describe("NetworkService (Prompt 10 §66–§73)", () => {
  it("lists networks grouped from recorded asset networks only (§70)", async () => {
    const { networks } = await makeService().listNetworks(user);
    expect(networks).toEqual([{ network: "192.0.2.0/24", hosts: 1, openPorts: 2, services: 3, findings: 2 }]);
  });

  it("host list is paginated, tenant-scoped and carries open-port counts", async () => {
    const res = await makeService().listHosts(user, { page: 1, pageSize: 20 });
    expect(res.total).toBe(1);
    expect(res.items[0]).toMatchObject({ host: "192.0.2.10", openPorts: 2, findings: 2, osHint: "Linux 5.15" });
    const other = await makeService().listHosts(foreign, { page: 1, pageSize: 20 });
    expect(other.items.map((i) => i.host)).toEqual(["198.51.100.7"]);
  });

  it("a foreign host id is a 404, never a leak (§83)", async () => {
    await expect(makeService().getHost(foreign, "h-1")).rejects.toBeInstanceOf(NotFoundException);
    await expect(makeService().getHost(user, "h-2")).rejects.toBeInstanceOf(NotFoundException);
    const detail = await makeService().getHost(user, "h-1");
    expect(detail.host).toBe("192.0.2.10");
    expect(detail.servicesDetail).toHaveLength(3);
  });

  it("scan summary counts the merged inventory (§72) and foreign scans 404", async () => {
    const summary = await makeService().scanNetworkSummary(user, "scan-1");
    expect(summary).toMatchObject({ hostsDiscovered: 1, openTcpPorts: 2, servicesIdentified: 2, tlsServices: 1, findings: 2, packetCaptures: 1 });
    expect(summary.chunks).toHaveLength(1);
    await expect(makeService().scanNetworkSummary(foreign, "scan-1")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("packet captures are tenant-isolated metadata — no bytes, ever", async () => {
    const { captures } = await makeService().listPacketCaptures(user, {});
    expect(captures).toHaveLength(1);
    expect(captures[0]).toMatchObject({ id: "cap-1", format: "PCAP", sha256: "a".repeat(64) });
    expect(JSON.stringify(captures)).not.toContain("cap-2");
    const { capture } = await makeService().loadCaptureForRawAccess(user, "cap-1");
    expect(capture.storageKey).toContain("scans/scan-1");
    await expect(makeService().loadCaptureForRawAccess(foreign, "cap-1")).rejects.toBeInstanceOf(NotFoundException);
  });
});
