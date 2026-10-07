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
}

/** Conservative defaults for one recon run. */
export const DEFAULT_DISCOVERY_BUDGET: DiscoveryBudget = {
  maxSubdomains: 5_000,
  maxResolvedHosts: 2_000,
  maxHttpTargets: 1_000,
  maxHistoricalUrls: 10_000,
  maxCrawlUrls: 5_000,
  maxTotalRequests: 20_000,
  maxDurationSeconds: 1_800,
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

export type BudgetKind = "subdomains" | "resolvedHosts" | "httpTargets" | "historicalUrls" | "crawlUrls" | "requests";

const KIND_TO_KEY: Record<BudgetKind, keyof DiscoveryBudget> = {
  subdomains: "maxSubdomains",
  resolvedHosts: "maxResolvedHosts",
  httpTargets: "maxHttpTargets",
  historicalUrls: "maxHistoricalUrls",
  crawlUrls: "maxCrawlUrls",
  requests: "maxTotalRequests",
};

/** Mutable per-scan counter the pipeline consults before accepting more
 *  discoveries. `now` is injectable so duration limits are testable. */
export class BudgetTracker {
  private readonly counts: Record<BudgetKind, number> = {
    subdomains: 0, resolvedHosts: 0, httpTargets: 0, historicalUrls: 0, crawlUrls: 0, requests: 0,
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
