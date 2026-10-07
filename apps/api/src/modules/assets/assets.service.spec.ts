import { NotFoundException } from "@nestjs/common";
import { AssetsService } from "./assets.service";

/**
 * Prompt 5 §48/§57: the inventory API is tenant-isolated (foreign ids are
 * 404s), filters behave, and the recon summary counts INVENTORY — assets,
 * services, endpoints, tools — never vulnerabilities.
 */

const user = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

const ASSETS = [
  {
    id: "a-1", workspaceId: "ws-org-1", host: "api.example.com", ip: "93.184.216.34", type: "SUBDOMAIN",
    scopeStatus: "IN_SCOPE", sources: ["subfinder", "amass"], httpStatus: 200, discoveredByScanId: "scan-1",
    services: [{ assetId: "a-1", port: 443, protocol: "tcp", name: "https" }],
    technologies: [{ assetId: "a-1", name: "nginx" }],
    _count: { services: 1, endpoints: 2 },
  },
  {
    id: "a-2", workspaceId: "ws-org-1", host: "cdn.vendor.example.net", ip: null, type: "SUBDOMAIN",
    scopeStatus: "OUT_OF_SCOPE", sources: ["subfinder"], httpStatus: null, discoveredByScanId: "scan-1",
    services: [], technologies: [], _count: { services: 0, endpoints: 0 },
  },
  {
    id: "a-3", workspaceId: "ws-org-2", host: "other.example.org", ip: null, type: "HOST",
    scopeStatus: "IN_SCOPE", sources: ["subfinder"], httpStatus: null, discoveredByScanId: "scan-9",
    services: [], technologies: [], _count: { services: 0, endpoints: 0 },
  },
];
const ENDPOINTS = [
  { id: "e-1", assetId: "a-1", url: "https://api.example.com/login", source: "gau", scopeStatus: "IN_SCOPE" },
  { id: "e-2", assetId: "a-1", url: "https://api.example.com/search", source: "katana", scopeStatus: "IN_SCOPE" },
  { id: "e-3", assetId: "a-3", url: "https://other.example.org/x", source: "gau", scopeStatus: "IN_SCOPE" },
];
const assetById = (id: string) => ASSETS.find((a) => a.id === id);

function matches(asset: (typeof ASSETS)[number], where: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (k === "workspaceId" && asset.workspaceId !== v) return false;
    if (k === "scopeStatus" && asset.scopeStatus !== v) return false;
    if (k === "discoveredByScanId" && asset.discoveredByScanId !== v) return false;
    if (k === "id" && asset.id !== v) return false;
    if (k === "sources") {
      const needle = (v as { array_contains: string[] }).array_contains[0]!;
      if (!asset.sources.includes(needle)) return false;
    }
    if (k === "technologies") {
      const name = (v as { some: { name: { contains: string } } }).some.name.contains.toLowerCase();
      if (!asset.technologies.some((t) => t.name.toLowerCase().includes(name))) return false;
    }
    if (k === "host") {
      const needle = (v as { contains: string }).contains.toLowerCase();
      if (!asset.host.includes(needle)) return false;
    }
  }
  return true;
}

function makeService() {
  const prisma = {
    workspace: {
      findFirst: async ({ where }: never) => {
        const org = (where as { organizationId: string }).organizationId;
        return { id: `ws-${org}`, organizationId: org };
      },
    },
    asset: {
      findMany: async ({ where }: never) => ASSETS.filter((a) => matches(a, where as Record<string, unknown>)),
      count: async ({ where }: never) => ASSETS.filter((a) => matches(a, where as Record<string, unknown>)).length,
      findFirst: async ({ where }: never) => ASSETS.find((a) => matches(a, where as Record<string, unknown>)) ?? null,
    },
    service: { findMany: async ({ where }: never) => ASSETS.flatMap((a) => a.services).filter((s) => s.assetId === (where as { assetId: string }).assetId) },
    endpoint: {
      findMany: async ({ where }: never) => {
        const w = where as { assetId?: string; asset?: { workspaceId: string; discoveredByScanId?: string }; scopeStatus?: string };
        return ENDPOINTS.filter((e) => {
          const asset = assetById(e.assetId)!;
          if (w.assetId && e.assetId !== w.assetId) return false;
          if (w.asset && asset.workspaceId !== w.asset.workspaceId) return false;
          if (w.asset?.discoveredByScanId && asset.discoveredByScanId !== w.asset.discoveredByScanId) return false;
          if (w.scopeStatus && e.scopeStatus !== w.scopeStatus) return false;
          return true;
        }).map((e) => ({ ...e, asset: { id: e.assetId, host: assetById(e.assetId)!.host } }));
      },
      count: async () => ENDPOINTS.length,
    },
    scan: {
      findFirst: async ({ where }: never) => {
        const w = where as { id: string; workspaceId: string };
        if (w.id === "scan-1" && w.workspaceId === "ws-org-1") return { id: "scan-1", workspaceId: "ws-org-1" };
        return null;
      },
    },
    toolExecution: {
      findMany: async () => [
        { tool: { slug: "subfinder", name: "Subfinder" }, status: "COMPLETED" },
        { tool: { slug: "dnsx", name: "dnsx" }, status: "COMPLETED" },
      ],
    },
  };
  return new AssetsService(prisma as never);
}

describe("AssetsService (Prompt 5 §48)", () => {
  it("lists only the caller's workspace assets, with filters", async () => {
    const svc = makeService();
    const all = await svc.listAssets(user as never, { page: 1, pageSize: 20 });
    expect(all.total).toBe(2);
    expect(all.items.map((a) => a.id)).toEqual(["a-1", "a-2"]);
    const inScope = await svc.listAssets(user as never, { page: 1, pageSize: 20, scopeStatus: "IN_SCOPE" });
    expect(inScope.items.map((a) => a.id)).toEqual(["a-1"]);
    const bySource = await svc.listAssets(user as never, { page: 1, pageSize: 20, source: "amass" });
    expect(bySource.items.map((a) => a.id)).toEqual(["a-1"]);
    const byTech = await svc.listAssets(user as never, { page: 1, pageSize: 20, technology: "nginx" });
    expect(byTech.items.map((a) => a.id)).toEqual(["a-1"]);
    const foreignList = await svc.listAssets(foreign as never, { page: 1, pageSize: 20 });
    expect(foreignList.items.map((a) => a.id)).toEqual(["a-3"]);
  });

  it("asset detail is a 404 for another tenant (§57)", async () => {
    const svc = makeService();
    const own = await svc.getAsset(user as never, "a-1");
    expect(own.host).toBe("api.example.com");
    await expect(svc.getAsset(foreign as never, "a-1")).rejects.toThrow(NotFoundException);
    await expect(svc.listAssetServices(foreign as never, "a-1")).rejects.toThrow(NotFoundException);
  });

  it("scan endpoints come only from assets that scan discovered", async () => {
    const svc = makeService();
    const eps = await svc.listScanEndpoints(user as never, "scan-1");
    expect(eps.map((e) => e.id).sort()).toEqual(["e-1", "e-2"]);
    await expect(svc.listScanEndpoints(foreign as never, "scan-1")).rejects.toThrow(NotFoundException);
  });

  it("recon summary counts inventory and tools — no vulnerability numbers", async () => {
    const svc = makeService();
    const summary = await svc.reconSummary(user as never, "scan-1");
    expect(summary.totalAssets).toBe(2);
    expect(summary.inScopeAssets).toBe(1);
    expect(summary.outOfScopeAssets).toBe(1);
    expect(summary.resolvedHosts).toBe(1);
    expect(summary.httpServices).toBe(1);
    expect(summary.technologies).toBe(1);
    expect(summary.totalEndpoints).toBe(2);
    expect(summary.historicalUrls).toBe(1); // gau
    expect(summary.crawlUrls).toBe(1); // katana
    expect(summary.bySource).toEqual({ subfinder: 2, amass: 1 });
    expect(summary.toolsRun.map((t) => t.slug)).toEqual(["subfinder", "dnsx"]);
    expect(JSON.stringify(summary)).not.toMatch(/vulnerabilit/i);
  });
});
