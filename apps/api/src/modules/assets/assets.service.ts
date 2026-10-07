import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";

export interface AssetListQuery {
  page: number;
  pageSize: number;
  scopeStatus?: string;
  technology?: string;
  source?: string;
  search?: string;
}

export interface EndpointListQuery {
  page: number;
  pageSize: number;
  scopeStatus?: string;
  search?: string;
  /** Prompt 6 §55 filters. */
  method?: string;
  endpointType?: string;
  source?: string;
}

/** Web-surface metrics over endpoint rows (Prompt 6 §54): counts of what
 *  discovery found — by provenance, type, status class and classification.
 *  Inventory numbers only, never vulnerability claims. */
export function summarizeWebSurface(endpoints: Array<Record<string, unknown>>) {
  const bySource: Record<string, number> = {};
  const byType: Record<string, number> = {};
  const byStatusClass: Record<string, number> = {};
  let parameters = 0;
  let forms = 0;
  let endpointsWithParameters = 0;
  const parameterNames = new Set<string>();
  for (const e of endpoints) {
    const sources = (e.sources as string[] | undefined) ?? (e.source ? [e.source as string] : []);
    for (const s of sources) bySource[s] = (bySource[s] ?? 0) + 1;
    const type = (e.endpointType as string) ?? "UNKNOWN";
    byType[type] = (byType[type] ?? 0) + 1;
    const status = e.statusCode as number | undefined;
    const cls = status === undefined ? "unknown" : `${Math.floor(status / 100)}xx`;
    byStatusClass[cls] = (byStatusClass[cls] ?? 0) + 1;
    const params = (e.parameters as Array<{ name: string }> | undefined) ?? [];
    parameters += params.length;
    if (params.length > 0) endpointsWithParameters++;
    for (const p of params) parameterNames.add(p.name);
    forms += ((e.forms as unknown[] | undefined) ?? []).length;
  }
  return {
    totalEndpoints: endpoints.length,
    inScopeEndpoints: endpoints.filter((e) => e.scopeStatus === "IN_SCOPE").length,
    outOfScopeEndpoints: endpoints.filter((e) => e.scopeStatus === "OUT_OF_SCOPE").length,
    apiEndpoints: endpoints.filter((e) => e.endpointType === "API").length,
    sensitiveRoutes: endpoints.filter((e) => e.classification === "SENSITIVE_ROUTE").length,
    javascriptResources: endpoints.filter((e) => /\.m?js($|\?)/.test(e.url as string)).length,
    endpointsBySource: bySource,
    endpointsByType: byType,
    endpointsByStatusClass: byStatusClass,
    parametersDiscovered: parameters,
    uniqueParameterNames: parameterNames.size,
    endpointsWithParameters,
    formsDiscovered: forms,
  };
}

/**
 * Asset / endpoint inventory API (Prompt 5 §48). Everything here is
 * READ-ONLY inventory: assets, services, technologies and endpoints that
 * authorized scans discovered. Every query is workspace-scoped through the
 * caller's organization (§57 tenant isolation) — an asset id from another
 * tenant is a 404, never a leak. Scan-scoped views key on the asset's
 * discoveredByScanId, recorded by the worker at persistence time.
 */
@Injectable()
export class AssetsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async listAssets(user: RequestUser, query: AssetListQuery) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const where: Record<string, unknown> = { workspaceId: workspace.id };
    if (query.scopeStatus) where.scopeStatus = query.scopeStatus;
    if (query.source) where.sources = { array_contains: [query.source] };
    if (query.technology) where.technologies = { some: { name: { contains: query.technology, mode: "insensitive" } } };
    if (query.search) where.host = { contains: query.search, mode: "insensitive" };
    const [items, total] = await Promise.all([
      this.prisma.asset.findMany({
        where,
        include: { technologies: { select: { name: true } }, _count: { select: { services: true, endpoints: true } } },
        orderBy: { host: "asc" },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.asset.count({ where }),
    ]);
    return { items, total, page: query.page, pageSize: query.pageSize };
  }

  async getAsset(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const asset = await this.prisma.asset.findFirst({
      where: { id, workspaceId: workspace.id },
      include: {
        target: { select: { id: true, value: true, type: true } },
        services: { orderBy: { port: "asc" } },
        technologies: { orderBy: { name: "asc" } },
        endpoints: { orderBy: { url: "asc" }, take: 500 },
      },
    });
    if (!asset) throw new NotFoundException("Asset not found");
    return asset;
  }

  async listAssetServices(user: RequestUser, id: string) {
    const asset = await this.ownedAsset(user, id);
    return this.prisma.service.findMany({ where: { assetId: asset.id }, orderBy: { port: "asc" } });
  }

  async listAssetEndpoints(user: RequestUser, id: string) {
    const asset = await this.ownedAsset(user, id);
    return this.prisma.endpoint.findMany({ where: { assetId: asset.id }, orderBy: { url: "asc" }, take: 1000 });
  }

  async listEndpoints(user: RequestUser, query: EndpointListQuery) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const where: Record<string, unknown> = { asset: { workspaceId: workspace.id } };
    if (query.scopeStatus) where.scopeStatus = query.scopeStatus;
    if (query.search) where.url = { contains: query.search, mode: "insensitive" };
    if (query.method) where.method = query.method.toUpperCase();
    if (query.endpointType) where.endpointType = query.endpointType;
    if (query.source) where.OR = [{ source: query.source }, { sources: { has: query.source } }];
    const [items, total] = await Promise.all([
      this.prisma.endpoint.findMany({
        where,
        include: { asset: { select: { id: true, host: true } } },
        orderBy: { url: "asc" },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
      this.prisma.endpoint.count({ where }),
    ]);
    return { items, total, page: query.page, pageSize: query.pageSize };
  }

  /** Endpoint detail (Prompt 6 §55): the endpoint with its classification,
   *  provenance and full parameter/form inventory. Tenant-isolated — a
   *  foreign endpoint id is a 404 (§57). */
  async getEndpoint(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const endpoint = await this.prisma.endpoint.findFirst({
      where: { id, asset: { workspaceId: workspace.id } },
      include: {
        asset: { select: { id: true, host: true } },
        parameters: { orderBy: { name: "asc" } },
        forms: true,
      },
    });
    if (!endpoint) throw new NotFoundException("Endpoint not found");
    return endpoint;
  }

  /** Parameters of one endpoint (§55): names, locations, provenance. */
  async listEndpointParameters(user: RequestUser, endpointId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const endpoint = await this.prisma.endpoint.findFirst({
      where: { id: endpointId, asset: { workspaceId: workspace.id } },
      select: { id: true },
    });
    if (!endpoint) throw new NotFoundException("Endpoint not found");
    return this.prisma.endpointParameter.findMany({
      where: { endpointId: endpoint.id },
      orderBy: { name: "asc" },
      take: 1000,
    });
  }

  /** Per-asset web surface (§55): the asset's endpoints with parameters,
   *  plus the §54 metrics computed over them. */
  async getAssetWebSurface(user: RequestUser, id: string) {
    const asset = await this.ownedAsset(user, id);
    const endpoints = await this.prisma.endpoint.findMany({
      where: { assetId: asset.id },
      include: { parameters: { orderBy: { name: "asc" } }, forms: true },
      orderBy: { url: "asc" },
      take: 2000,
    });
    return { assetId: asset.id, ...summarizeWebSurface(endpoints as never), endpoints };
  }

  /** Scan web-surface summary (§54/§55): what content/parameter discovery
   *  found in this scan — endpoints by source/type/status, parameters,
   *  forms, sensitive routes, and the discovery tools that ran. */
  async webSurfaceSummary(user: RequestUser, scanId: string) {
    await this.ownedScan(user, scanId);
    const workspace = await resolveWorkspace(this.prisma, user);
    const endpoints = await this.prisma.endpoint.findMany({
      where: { asset: { workspaceId: workspace.id, discoveredByScanId: scanId } },
      include: {
        parameters: { select: { name: true } },
        forms: { select: { id: true } },
        asset: { select: { id: true, host: true } },
      },
      take: 10000,
    });
    const toolsRun = await this.prisma.toolExecution.findMany({
      where: { scanId },
      include: { tool: { select: { slug: true, name: true } } },
      orderBy: { createdAt: "asc" },
    });
    const discoveryTools = ["ffuf", "feroxbuster", "gobuster", "wfuzz", "arjun", "katana", "gau", "waybackurls"];
    return {
      scanId,
      ...summarizeWebSurface(endpoints as never),
      toolsRun: toolsRun.map((t) => ({ slug: t.tool?.slug, name: t.tool?.name, status: t.status })),
      contentDiscoveryToolsRun: toolsRun.filter((t) => discoveryTools.includes(t.tool?.slug ?? "")).map((t) => t.tool?.slug),
    };
  }

  async listScanAssets(user: RequestUser, scanId: string) {
    const scan = await this.ownedScan(user, scanId);
    void scan;
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.asset.findMany({
      where: { workspaceId: workspace.id, discoveredByScanId: scanId },
      include: { technologies: { select: { name: true } }, _count: { select: { services: true, endpoints: true } } },
      orderBy: { host: "asc" },
      take: 2000,
    });
  }

  async listScanEndpoints(user: RequestUser, scanId: string) {
    await this.ownedScan(user, scanId);
    const workspace = await resolveWorkspace(this.prisma, user);
    return this.prisma.endpoint.findMany({
      where: { asset: { workspaceId: workspace.id, discoveredByScanId: scanId } },
      include: { asset: { select: { id: true, host: true } } },
      orderBy: { url: "asc" },
      take: 2000,
    });
  }

  /** Recon summary (§46): inventory metrics for one scan — counts of what
   *  was discovered, never vulnerability claims. */
  async reconSummary(user: RequestUser, scanId: string) {
    const scan = await this.ownedScan(user, scanId);
    const workspace = await resolveWorkspace(this.prisma, user);
    const assets = await this.prisma.asset.findMany({
      where: { workspaceId: workspace.id, discoveredByScanId: scanId },
      include: { services: true, technologies: true, _count: { select: { endpoints: true } } },
      take: 5000,
    });
    const toolsRun = await this.prisma.toolExecution.findMany({
      where: { scanId },
      include: { tool: { select: { slug: true, name: true } } },
      orderBy: { createdAt: "asc" },
    });
    const bySource: Record<string, number> = {};
    for (const a of assets) for (const s of (a.sources as string[]) ?? []) bySource[s] = (bySource[s] ?? 0) + 1;
    const endpoints = await this.prisma.endpoint.findMany({
      where: { asset: { workspaceId: workspace.id, discoveredByScanId: scanId } },
      select: { source: true, scopeStatus: true },
      take: 10000,
    });
    return {
      scanId,
      profile: (scan as { profile?: string }).profile ?? undefined,
      totalAssets: assets.length,
      inScopeAssets: assets.filter((a) => a.scopeStatus === "IN_SCOPE").length,
      outOfScopeAssets: assets.filter((a) => a.scopeStatus === "OUT_OF_SCOPE").length,
      subdomains: assets.filter((a) => a.type === "SUBDOMAIN").length,
      resolvedHosts: assets.filter((a) => a.ip).length,
      httpServices: assets.reduce((n, a) => n + a.services.filter((s) => s.port === 80 || s.port === 443).length, 0),
      totalServices: assets.reduce((n, a) => n + a.services.length, 0),
      technologies: assets.reduce((n, a) => n + a.technologies.length, 0),
      totalEndpoints: endpoints.length,
      historicalUrls: endpoints.filter((e) => e.source === "gau" || e.source === "waybackurls").length,
      crawlUrls: endpoints.filter((e) => e.source === "katana").length,
      outOfScopeEndpoints: endpoints.filter((e) => e.scopeStatus === "OUT_OF_SCOPE").length,
      bySource,
      toolsRun: toolsRun.map((t) => ({ slug: t.tool?.slug, name: t.tool?.name, status: t.status })),
    };
  }

  private async ownedAsset(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const asset = await this.prisma.asset.findFirst({ where: { id, workspaceId: workspace.id }, select: { id: true } });
    if (!asset) throw new NotFoundException("Asset not found");
    return asset;
  }

  private async ownedScan(user: RequestUser, scanId: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    return scan;
  }
}
