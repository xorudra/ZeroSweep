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
  { id: "e-1", assetId: "a-1", url: "https://api.example.com/login", method: "GET", statusCode: 200, endpointType: "PAGE", classification: null, source: "gau", sources: ["gau"], scopeStatus: "IN_SCOPE" },
  { id: "e-2", assetId: "a-1", url: "https://api.example.com/search", method: "GET", statusCode: 200, endpointType: "PAGE", classification: null, source: "katana", sources: ["katana"], scopeStatus: "IN_SCOPE" },
  { id: "e-3", assetId: "a-3", url: "https://other.example.org/x", method: "GET", statusCode: 200, endpointType: "PAGE", classification: null, source: "gau", sources: ["gau"], scopeStatus: "IN_SCOPE" },
  { id: "e-4", assetId: "a-1", url: "https://api.example.com/admin", method: "GET", statusCode: 200, endpointType: "PAGE", classification: "SENSITIVE_ROUTE", source: "ffuf", sources: ["ffuf", "feroxbuster", "gobuster"], scopeStatus: "IN_SCOPE" },
  { id: "e-5", assetId: "a-1", url: "https://api.example.com/api/users", method: "GET", statusCode: 200, endpointType: "API", classification: null, source: "ffuf", sources: ["ffuf"], scopeStatus: "IN_SCOPE" },
];
const PARAMETERS = [
  { id: "p-1", endpointId: "e-2", name: "q", location: "QUERY", sources: ["katana"], confidence: 1 },
  { id: "p-2", endpointId: "e-2", name: "id", location: "QUERY", sources: ["arjun", "wfuzz"], confidence: 0.9 },
  { id: "p-3", endpointId: "e-5", name: "limit", location: "QUERY", sources: ["arjun"], confidence: 0.9 },
  { id: "p-4", endpointId: "e-5", name: "offset", location: "QUERY", sources: ["arjun"], confidence: 0.9 },
];
const assetById = (id: string) => ASSETS.find((a) => a.id === id);

interface EndpointWhere {
  assetId?: string;
  asset?: { workspaceId: string; discoveredByScanId?: string };
  scopeStatus?: string;
  method?: string;
  endpointType?: string;
  url?: { contains: string };
  OR?: Array<{ source?: string; sources?: { has: string } }>;
}
function filterEndpoints(where: EndpointWhere) {
  return ENDPOINTS.filter((e) => {
    const asset = assetById(e.assetId)!;
    if (where.assetId && e.assetId !== where.assetId) return false;
    if (where.asset && asset.workspaceId !== where.asset.workspaceId) return false;
    if (where.asset?.discoveredByScanId && asset.discoveredByScanId !== where.asset.discoveredByScanId) return false;
    if (where.scopeStatus && e.scopeStatus !== where.scopeStatus) return false;
    if (where.method && e.method !== where.method) return false;
    if (where.endpointType && e.endpointType !== where.endpointType) return false;
    if (where.url && !e.url.toLowerCase().includes(where.url.contains.toLowerCase())) return false;
    if (where.OR && !where.OR.some((cond) => (cond.source !== undefined && e.source === cond.source) || (cond.sources !== undefined && e.sources.includes(cond.sources.has)))) return false;
    return true;
  });
}

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
      findMany: async ({ where }: never) => filterEndpoints(where as never).map((e) => ({
        ...e,
        asset: { id: e.assetId, host: assetById(e.assetId)!.host },
        parameters: PARAMETERS.filter((p) => p.endpointId === e.id),
        forms: [],
      })),
      findFirst: async ({ where }: never) => {
        const w = where as { id?: string; asset?: { workspaceId: string } };
        const found = ENDPOINTS.find((e) => {
          if (w.id && e.id !== w.id) return false;
          if (w.asset && assetById(e.assetId)!.workspaceId !== w.asset.workspaceId) return false;
          return true;
        });
        if (!found) return null;
        return { ...found, asset: { id: found.assetId, host: assetById(found.assetId)!.host }, parameters: PARAMETERS.filter((p) => p.endpointId === found.id), forms: [] };
      },
      count: async ({ where }: never) => filterEndpoints(where as never).length,
    },
    endpointParameter: {
      findMany: async ({ where }: never) => PARAMETERS.filter((p) => p.endpointId === (where as { endpointId: string }).endpointId),
      count: async () => PARAMETERS.length,
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
    expect(eps.map((e) => e.id).sort()).toEqual(["e-1", "e-2", "e-4", "e-5"]);
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
    expect(summary.totalEndpoints).toBe(4);
    expect(summary.historicalUrls).toBe(1); // gau
    expect(summary.crawlUrls).toBe(1); // katana
    expect(summary.bySource).toEqual({ subfinder: 2, amass: 1 });
    expect(summary.toolsRun.map((t) => t.slug)).toEqual(["subfinder", "dnsx"]);
    expect(JSON.stringify(summary)).not.toMatch(/vulnerabilit/i);
  });
});

describe("AssetsService — Prompt 6 web surface (§55)", () => {
  it("endpoint list filters by type, method and provenance source", async () => {
    const svc = makeService();
    const api = await svc.listEndpoints(user as never, { page: 1, pageSize: 20, endpointType: "API" });
    expect(api.items.map((e) => e.id)).toEqual(["e-5"]);
    const byFerox = await svc.listEndpoints(user as never, { page: 1, pageSize: 20, source: "feroxbuster" });
    expect(byFerox.items.map((e) => e.id)).toEqual(["e-4"]); // matched via the sources provenance list
    const posts = await svc.listEndpoints(user as never, { page: 1, pageSize: 20, method: "POST" });
    expect(posts.items).toEqual([]);
    const foreignList = await svc.listEndpoints(foreign as never, { page: 1, pageSize: 20 });
    expect(foreignList.items.map((e) => e.id)).toEqual(["e-3"]);
  });

  it("endpoint detail carries classification + parameters; foreign ids 404 (§57)", async () => {
    const svc = makeService();
    const detail = await svc.getEndpoint(user as never, "e-4");
    expect(detail.classification).toBe("SENSITIVE_ROUTE");
    expect(detail.sources).toEqual(["ffuf", "feroxbuster", "gobuster"]);
    await expect(svc.getEndpoint(foreign as never, "e-4")).rejects.toThrow(NotFoundException);
    const params = await svc.listEndpointParameters(user as never, "e-2");
    expect(params.map((p) => p.name).sort()).toEqual(["id", "q"]);
    expect(params.find((p) => p.name === "id")!.sources).toEqual(["arjun", "wfuzz"]);
    await expect(svc.listEndpointParameters(foreign as never, "e-2")).rejects.toThrow(NotFoundException);
  });

  it("per-asset web surface summarizes endpoints + parameters", async () => {
    const svc = makeService();
    const surface = await svc.getAssetWebSurface(user as never, "a-1");
    expect(surface.totalEndpoints).toBe(4);
    expect(surface.apiEndpoints).toBe(1);
    expect(surface.sensitiveRoutes).toBe(1);
    expect(surface.parametersDiscovered).toBe(4);
    expect(surface.uniqueParameterNames).toBe(4);
    expect(surface.endpointsWithParameters).toBe(2);
    expect(surface.endpointsBySource).toEqual({ gau: 1, katana: 1, ffuf: 2, feroxbuster: 1, gobuster: 1 });
    await expect(svc.getAssetWebSurface(foreign as never, "a-1")).rejects.toThrow(NotFoundException);
  });

  it("scan web-surface summary counts discovery output — inventory only (§54)", async () => {
    const svc = makeService();
    const summary = await svc.webSurfaceSummary(user as never, "scan-1");
    expect(summary.totalEndpoints).toBe(4);
    expect(summary.inScopeEndpoints).toBe(4);
    expect(summary.endpointsByType).toEqual({ PAGE: 3, API: 1 });
    expect(summary.endpointsByStatusClass).toEqual({ "2xx": 4 });
    expect(summary.parametersDiscovered).toBe(4);
    expect(summary.formsDiscovered).toBe(0);
    expect(JSON.stringify(summary)).not.toMatch(/vulnerabilit/i);
    await expect(svc.webSurfaceSummary(foreign as never, "scan-1")).rejects.toThrow(NotFoundException);
  });
});
