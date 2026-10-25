/**
 * Proxy/scanner budget + rate limits (Prompt 8 §44–§45). Extends the
 * platform budget family (DiscoveryBudget, VulnBudget) with the ceilings
 * interactive connectors must respect. Administrator hard caps win over
 * every profile and over every scanner-vendor default: ZeroSweep rate
 * limits apply even when the scanner itself would go faster (§45).
 */
export interface ProxyBudget {
  /** Requests issued THROUGH the proxy/scanner against the target. */
  maxProxyRequests: number;
  /** Traffic transactions imported/analyzed per scan. */
  maxPassiveTransactions: number;
  /** Crawl requests issued by connector-driven crawling. */
  maxCrawlerRequests: number;
  /** Requests an APPROVED active scan may issue (0 = active scanning off). */
  maxActiveScanRequests: number;
  /** Wall-clock ceiling for an approved active scan, seconds. */
  maxActiveScanDurationSeconds: number;
  /** Raw evidence retained per scan, bytes. */
  maxEvidenceBytes: number;
  /** Endpoints imported from one connector per scan. */
  maxImportedEndpoints: number;
  /** Issues imported from one connector per scan. */
  maxImportedIssues: number;
}

export const DEFAULT_PROXY_BUDGET: ProxyBudget = {
  maxProxyRequests: 10_000,
  maxPassiveTransactions: 10_000,
  maxCrawlerRequests: 5_000,
  maxActiveScanRequests: 0,
  maxActiveScanDurationSeconds: 1_800,
  maxEvidenceBytes: 50 * 1024 * 1024,
  maxImportedEndpoints: 10_000,
  maxImportedIssues: 5_000,
};

export const ADMIN_PROXY_CAPS: ProxyBudget = {
  maxProxyRequests: 100_000,
  maxPassiveTransactions: 100_000,
  maxCrawlerRequests: 50_000,
  maxActiveScanRequests: 50_000,
  maxActiveScanDurationSeconds: 7_200,
  maxEvidenceBytes: 500 * 1024 * 1024,
  maxImportedEndpoints: 100_000,
  maxImportedIssues: 50_000,
};

const KEYS = Object.keys(DEFAULT_PROXY_BUDGET) as (keyof ProxyBudget)[];

/** Clamp a requested budget to defaults/admin caps (§44). Zero is a
 *  legitimate request for maxActiveScanRequests (it DISABLES active
 *  scanning), so it is honoured rather than replaced by the default. */
export function clampProxyBudget(requested: Partial<ProxyBudget> = {}): ProxyBudget {
  const out = { ...DEFAULT_PROXY_BUDGET };
  for (const key of KEYS) {
    const v = requested[key];
    if (typeof v === "number" && Number.isFinite(v) && v >= 0) {
      out[key] = Math.min(Math.floor(v), ADMIN_PROXY_CAPS[key]);
    }
  }
  return out;
}

/** Connector rate limits (§45): requests/sec, concurrency, inter-request
 *  delay. Connector plans carry these; a scanner configured more
 *  aggressively than this is clamped by the connector, not obeyed. */
export interface ConnectorRateLimits {
  requestsPerSecond: number;
  concurrency: number;
  delayMs: number;
}

export const DEFAULT_CONNECTOR_RATE_LIMITS: ConnectorRateLimits = {
  requestsPerSecond: 10,
  concurrency: 2,
  delayMs: 0,
};

export const ADMIN_CONNECTOR_RATE_CAPS: ConnectorRateLimits = {
  requestsPerSecond: 50,
  concurrency: 8,
  delayMs: 60_000,
};

export function clampConnectorRateLimits(requested: Partial<ConnectorRateLimits> = {}): ConnectorRateLimits {
  const rps = typeof requested.requestsPerSecond === "number" && requested.requestsPerSecond > 0
    ? Math.min(requested.requestsPerSecond, ADMIN_CONNECTOR_RATE_CAPS.requestsPerSecond)
    : DEFAULT_CONNECTOR_RATE_LIMITS.requestsPerSecond;
  const concurrency = typeof requested.concurrency === "number" && requested.concurrency > 0
    ? Math.min(Math.floor(requested.concurrency), ADMIN_CONNECTOR_RATE_CAPS.concurrency)
    : DEFAULT_CONNECTOR_RATE_LIMITS.concurrency;
  const delayMs = typeof requested.delayMs === "number" && requested.delayMs >= 0
    ? Math.min(Math.floor(requested.delayMs), ADMIN_CONNECTOR_RATE_CAPS.delayMs)
    : DEFAULT_CONNECTOR_RATE_LIMITS.delayMs;
  return { requestsPerSecond: rps, concurrency, delayMs };
}
