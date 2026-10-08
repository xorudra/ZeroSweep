/**
 * Endpoint identity, content-discovery normalization and crawl policy
 * (Prompt 32 §23–§29, §34).
 *
 * Endpoint identity is origin + method + normalized path template —
 * volatile parameter VALUES are never part of identity (§29), so the
 * same route discovered by ffuf, Feroxbuster, Gobuster, Wfuzz, Katana
 * and historical sources converges to ONE canonical endpoint with many
 * observations (§24).
 */

export interface DiscoveredPathObservation {
  tool: string;
  url: string;
  method?: string;
  statusCode?: number;
  contentLength?: number;
  contentType?: string;
  redirectLocation?: string;
}

export interface CanonicalEndpointObservation {
  identity: string;
  origin: string;
  method: string;
  path: string;
  sources: string[];
  observations: number;
  statusCodes: number[];
  contentTypes: string[];
}

/** Replace volatile path segments (ids, uuids, numbers) with a template. */
export function normalizePathTemplate(pathname: string): string {
  return pathname
    .split("/")
    .map((seg) => {
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return "{uuid}";
      if (/^\d+$/.test(seg)) return "{id}";
      if (/^[0-9a-f]{24,}$/i.test(seg)) return "{hex}";
      return seg;
    })
    .join("/") || "/";
}

export function endpointIdentity(url: string, method = "GET"): { identity: string; origin: string; path: string } | null {
  try {
    const u = new URL(url);
    const origin = `${u.protocol}//${u.host.toLowerCase()}`;
    const path = normalizePathTemplate(u.pathname);
    return { identity: `${method.toUpperCase()} ${origin}${path}`, origin, path };
  } catch {
    return null;
  }
}

/** §23/§24: merge multi-tool observations into canonical endpoints. */
export function mergeContentDiscovery(observations: DiscoveredPathObservation[]): CanonicalEndpointObservation[] {
  const byIdentity = new Map<string, CanonicalEndpointObservation>();
  for (const obs of observations) {
    const id = endpointIdentity(obs.url, obs.method ?? "GET");
    if (!id) continue;
    const existing = byIdentity.get(id.identity);
    if (existing) {
      existing.observations += 1;
      if (!existing.sources.includes(obs.tool)) existing.sources.push(obs.tool);
      if (obs.statusCode !== undefined && !existing.statusCodes.includes(obs.statusCode)) existing.statusCodes.push(obs.statusCode);
      if (obs.contentType && !existing.contentTypes.includes(obs.contentType)) existing.contentTypes.push(obs.contentType);
    } else {
      byIdentity.set(id.identity, {
        identity: id.identity, origin: id.origin, method: (obs.method ?? "GET").toUpperCase(), path: id.path,
        sources: [obs.tool], observations: 1,
        statusCodes: obs.statusCode !== undefined ? [obs.statusCode] : [],
        contentTypes: obs.contentType ? [obs.contentType] : [],
      });
    }
  }
  return [...byIdentity.values()].sort((a, b) => a.identity.localeCompare(b.identity));
}

/**
 * §27: dangerous-path exclusion. Endpoints whose interaction could
 * change state destructively are excluded from AUTOMATIC interaction
 * (they remain in inventory as observations). Patterns are platform
 * defaults; a workspace policy may add more, never remove these.
 */
export const DANGEROUS_PATH_PATTERNS: readonly RegExp[] = [
  /\/(delete|destroy|remove|purge|drop)(\/|$)/i,
  /\/logout(\/|$)/i,
  /\/(payment|purchase|checkout|pay|order\/confirm)(\/|$)/i,
  /\/admin\/(delete|ban|disable|reset-password)(\/|$)/i,
  /\/(unsubscribe|opt-out)(\/|$)/i,
];

export function isDangerousPath(pathname: string, extraPatterns: string[] = []): boolean {
  if (DANGEROUS_PATH_PATTERNS.some((re) => re.test(pathname))) return true;
  return extraPatterns.some((p) => pathname.toLowerCase().includes(p.toLowerCase()));
}

/** §26: crawl policy, clamped to platform hard bounds. */
export interface CrawlPolicy {
  maxDepth: number;
  maxUrls: number;
  sameOriginOnly: boolean;
  includeSubdomains: boolean;
  queryHandling: "KEEP_TEMPLATE" | "STRIP";
  excludedPaths: string[];
}

export const CRAWL_HARD_BOUNDS = { maxDepth: 5, maxUrls: 10_000 } as const;

export function clampCrawlPolicy(requested: Partial<CrawlPolicy> = {}): CrawlPolicy {
  return {
    maxDepth: Math.min(CRAWL_HARD_BOUNDS.maxDepth, Math.max(0, Math.floor(requested.maxDepth ?? 3))),
    maxUrls: Math.min(CRAWL_HARD_BOUNDS.maxUrls, Math.max(1, Math.floor(requested.maxUrls ?? 1_000))),
    sameOriginOnly: requested.sameOriginOnly !== false,
    includeSubdomains: requested.includeSubdomains === true,
    queryHandling: requested.queryHandling === "STRIP" ? "STRIP" : "KEEP_TEMPLATE",
    excludedPaths: [...new Set(requested.excludedPaths ?? [])],
  };
}

/**
 * §34: historical URLs (gau/waybackurls) are CANDIDATE endpoints. They
 * are inventoried, never automatically requested — activation requires
 * the normal scan pipeline against the authorized scope snapshot.
 */
export function classifyHistoricalUrl(url: string): { candidate: true; note: string } {
  void url;
  return { candidate: true, note: "historical URL — candidate endpoint only, not actively requested (§34)" };
}
