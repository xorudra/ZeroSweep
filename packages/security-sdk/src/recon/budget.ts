/**
 * Discovery budget (Prompt 5 §27–§28). Recon must never be unbounded:
 * every scan carries a budget of ceilings, administrators set hard maximums,
 * and profiles/users may only request LOWER values.
 */

export interface DiscoveryBudget {
  maxSubdomains: number;
  maxResolvedHosts: number;
  maxHttpTargets: number;
  maxHistoricalUrls: number;
  maxCrawlUrls: number;
  maxTotalRequests: number;
  maxDurationSeconds: number;
  /** Web content/parameter discovery ceilings (Prompt 6 §14). */
  maxContentRequests: number;
  maxDirectories: number;
  maxFiles: number;
  maxRecursionDepth: number;
  maxParameterRequests: number;
  maxVhostRequests: number;
  maxWordlistEntries: number;
  /** API security engine ceilings (Prompt 9 §61). */
  maxApiRequests: number;
  maxApiRoutes: number;
  maxSchemaOperations: number;
  maxGraphqlOperations: number;
  maxWebSocketEndpoints: number;
  /** Maximum imported specification size in BYTES (§7/§66). */
  maxSpecSize: number;
  maxTransactions: number;
  maxJwtTokensAnalyzed: number;
}

/** Conservative defaults for one recon run. Content discovery is
 *  intrusive-adjacent (Prompt 6 §15): its defaults stay deliberately low —
 *  the objective is assessment, not load testing. */
export const DEFAULT_DISCOVERY_BUDGET: DiscoveryBudget = {
  maxSubdomains: 5_000,
  maxResolvedHosts: 2_000,
  maxHttpTargets: 1_000,
  maxHistoricalUrls: 10_000,
  maxCrawlUrls: 5_000,
  maxTotalRequests: 20_000,
  maxDurationSeconds: 1_800,
  maxContentRequests: 5_000,
  maxDirectories: 2_000,
  maxFiles: 2_000,
  maxRecursionDepth: 3,
  maxParameterRequests: 2_000,
  maxVhostRequests: 1_000,
  maxWordlistEntries: 10_000,
  // Prompt 9 §61: API testing stays bounded and read-leaning by default.
  maxApiRequests: 5_000,
  maxApiRoutes: 2_000,
  maxSchemaOperations: 500,
  maxGraphqlOperations: 200,
  maxWebSocketEndpoints: 100,
  maxSpecSize: 5 * 1024 * 1024,
  maxTransactions: 5_000,
  maxJwtTokensAnalyzed: 50,
};

/** Administrator hard ceilings — no profile may exceed these. */
export const ADMIN_DISCOVERY_CAPS: DiscoveryBudget = {
  maxSubdomains: 50_000,
  maxResolvedHosts: 20_000,
  maxHttpTargets: 10_000,
  maxHistoricalUrls: 100_000,
  maxCrawlUrls: 50_000,
  maxTotalRequests: 200_000,
  maxDurationSeconds: 7_200,
  maxContentRequests: 50_000,
  maxDirectories: 20_000,
  maxFiles: 20_000,
  maxRecursionDepth: 6,
  maxParameterRequests: 20_000,
  maxVhostRequests: 10_000,
  maxWordlistEntries: 100_000,
  maxApiRequests: 50_000,
  maxApiRoutes: 20_000,
  maxSchemaOperations: 5_000,
  maxGraphqlOperations: 2_000,
  maxWebSocketEndpoints: 1_000,
  maxSpecSize: 25 * 1024 * 1024,
  maxTransactions: 50_000,
  maxJwtTokensAnalyzed: 500,
};

const KEYS = Object.keys(DEFAULT_DISCOVERY_BUDGET) as (keyof DiscoveryBudget)[];

/** Clamp a requested budget into [1, admin cap]; unspecified fields take the
 *  conservative default. Requests above the default are honoured only up to
 *  the admin cap — never beyond it. */
export function clampDiscoveryBudget(requested: Partial<DiscoveryBudget> = {}): DiscoveryBudget {
  const out = { ...DEFAULT_DISCOVERY_BUDGET };
  for (const key of KEYS) {
    const v = requested[key];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      out[key] = Math.min(Math.floor(v), ADMIN_DISCOVERY_CAPS[key]);
    }
  }
  return out;
}

export type BudgetKind = "subdomains" | "resolvedHosts" | "httpTargets" | "historicalUrls" | "crawlUrls" | "requests"
  | "contentRequests" | "directories" | "files" | "parameterRequests" | "vhostRequests"
  | "apiRequests" | "apiRoutes" | "schemaOperations" | "graphqlOperations" | "jwtTokens";

const KIND_TO_KEY: Record<BudgetKind, keyof DiscoveryBudget> = {
  subdomains: "maxSubdomains",
  resolvedHosts: "maxResolvedHosts",
  httpTargets: "maxHttpTargets",
  historicalUrls: "maxHistoricalUrls",
  crawlUrls: "maxCrawlUrls",
  requests: "maxTotalRequests",
  contentRequests: "maxContentRequests",
  directories: "maxDirectories",
  files: "maxFiles",
  parameterRequests: "maxParameterRequests",
  vhostRequests: "maxVhostRequests",
  apiRequests: "maxApiRequests",
  apiRoutes: "maxApiRoutes",
  schemaOperations: "maxSchemaOperations",
  graphqlOperations: "maxGraphqlOperations",
  jwtTokens: "maxJwtTokensAnalyzed",
};

/** Mutable per-scan counter the pipeline consults before accepting more
 *  discoveries. `now` is injectable so duration limits are testable. */
export class BudgetTracker {
  private readonly counts: Record<BudgetKind, number> = {
    subdomains: 0, resolvedHosts: 0, httpTargets: 0, historicalUrls: 0, crawlUrls: 0, requests: 0,
    contentRequests: 0, directories: 0, files: 0, parameterRequests: 0, vhostRequests: 0,
    apiRequests: 0, apiRoutes: 0, schemaOperations: 0, graphqlOperations: 0, jwtTokens: 0,
  };
  private readonly startedAt: number;

  constructor(
    private readonly budget: DiscoveryBudget,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.startedAt = this.now();
  }

  /** Try to consume `n` units of a budget kind; consumes nothing and returns
   *  false when the ceiling would be exceeded. */
  tryConsume(kind: BudgetKind, n = 1): boolean {
    if (this.durationExceeded()) return false;
    const key = KIND_TO_KEY[kind];
    if (this.counts[kind] + n > this.budget[key]) return false;
    this.counts[kind] += n;
    return true;
  }

  remaining(kind: BudgetKind): number {
    return Math.max(0, this.budget[KIND_TO_KEY[kind]] - this.counts[kind]);
  }

  durationExceeded(): boolean {
    return this.now() - this.startedAt > this.budget.maxDurationSeconds * 1000;
  }

  snapshot(): Record<BudgetKind, number> & { durationSeconds: number } {
    return { ...this.counts, durationSeconds: Math.floor((this.now() - this.startedAt) / 1000) };
  }
}
