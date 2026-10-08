/**
 * Usage metering & quotas (Prompt 40 §38–§53).
 *
 * Canonical semantics (§41): each metric has ONE definition, used by
 * every service. Raw UsageEvent rows are the authoritative billable
 * record (§44); aggregates are derived. Recording is idempotent on the
 * caller-supplied idempotency key (§42/§218) — retrying a job never
 * double-charges.
 *
 * Metering NEVER fabricates numbers (§298): usage is computed from real
 * events/rows or reported as null.
 */

export const USAGE_METRICS = [
  "ACTIVE_ASSETS",
  "SCANNED_ASSETS",
  "SCAN_JOBS",
  "WEB_SCAN_JOBS",
  "API_SCAN_JOBS",
  "NETWORK_SCAN_JOBS",
  "CLOUD_ACCOUNTS",
  "REPOSITORIES",
  "CONTAINER_IMAGES",
  "MOBILE_ARTIFACTS",
  "BINARY_ARTIFACTS",
  "AI_REQUESTS",
  "AI_TOKENS",
  "REPORTS_GENERATED",
  "STORAGE_BYTES",
  "CLIENT_USERS",
] as const;
export type UsageMetric = (typeof USAGE_METRICS)[number];

/** Canonical metric definitions (§41) — the single meaning of each metric. */
export const USAGE_METRIC_DEFINITIONS: Record<UsageMetric, string> = {
  ACTIVE_ASSETS: "Distinct assets in ACTIVE state within the organization during the period.",
  SCANNED_ASSETS: "Distinct assets that were the target of at least one completed scan job in the period.",
  SCAN_JOBS: "Scan jobs started (governed orchestration executions), counted once per job id.",
  WEB_SCAN_JOBS: "Scan jobs whose profile is a web assessment.",
  API_SCAN_JOBS: "Scan jobs whose profile is an API assessment.",
  NETWORK_SCAN_JOBS: "Scan jobs whose profile is a network assessment.",
  CLOUD_ACCOUNTS: "Cloud accounts connected for assessment during the period.",
  REPOSITORIES: "Source repositories registered for code security assessment.",
  CONTAINER_IMAGES: "Distinct container image digests submitted for assessment.",
  MOBILE_ARTIFACTS: "Mobile artifacts (APK/IPA) accepted for static analysis.",
  BINARY_ARTIFACTS: "Binary artifacts accepted for static analysis.",
  AI_REQUESTS: "AI copilot requests processed by the AI service.",
  AI_TOKENS: "Provider-reported AI tokens; null when the provider reports none (never estimated).",
  REPORTS_GENERATED: "Report snapshots generated (one per snapshot, not per download).",
  STORAGE_BYTES: "Bytes held in object storage for the organization at period end.",
  CLIENT_USERS: "Client-portal users linked to the organization.",
};

export function isUsageMetric(value: string): value is UsageMetric {
  return (USAGE_METRICS as readonly string[]).includes(value);
}

/** Quota dimensions (§46) — plan-level limits distinct from usage metrics. */
export const QUOTA_DIMENSIONS = [
  "ASSETS",
  "USERS",
  "WORKSPACES",
  "CONCURRENT_SCANS",
  "MONTHLY_SCANS",
  "AI_REQUESTS",
  "STORAGE_BYTES",
  "REPORTS",
  "INTEGRATIONS",
  "CLIENT_USERS",
] as const;
export type QuotaDimension = (typeof QUOTA_DIMENSIONS)[number];

/**
 * Platform-wide fair-use safety ceilings (§53): independent of paid
 * quota and of subscription tier (§175). A higher plan NEVER raises
 * these (§52/§298).
 */
export const FAIR_USE_CEILINGS = {
  MAX_TOOL_CONCURRENCY_PER_JOB: 8,
  MAX_UPLOAD_BYTES: 536_870_912, // 512 MiB
  MAX_JOB_DURATION_SECONDS: 14_400, // 4 h
  MAX_SCANNER_OUTPUT_BYTES: 268_435_456, // 256 MiB
  MAX_API_REQUESTS_PER_MINUTE_PER_USER: 600,
} as const;

export interface QuotaEvaluation {
  dimension: string;
  allowed: boolean;
  currentUsage: number;
  limit: number | null; // null = unlimited by plan
  remaining: number | null;
  overLimit: boolean;
}

/** Pure quota check (§48). `limit === null` means the plan does not cap it. */
export function evaluateQuota(input: {
  dimension: string;
  currentUsage: number;
  requested: number;
  limit: number | null;
}): QuotaEvaluation {
  const { dimension, currentUsage, requested, limit } = input;
  if (limit === null) {
    return { dimension, allowed: true, currentUsage, limit, remaining: null, overLimit: false };
  }
  const allowed = currentUsage + requested <= limit;
  return {
    dimension,
    allowed,
    currentUsage,
    limit,
    remaining: Math.max(0, limit - currentUsage),
    overLimit: currentUsage > limit,
  };
}

/** Structured quota-failure body (§51). */
export function quotaExceededBody(evaluation: QuotaEvaluation, period: string, upgradeAvailable: boolean) {
  return {
    error: "QUOTA_EXCEEDED",
    quota: evaluation.dimension,
    currentUsage: evaluation.currentUsage,
    limit: evaluation.limit,
    period,
    upgradeAvailable,
    message: `Quota exceeded for ${evaluation.dimension}: ${evaluation.currentUsage}/${evaluation.limit} used in ${period}. Existing data remains readable and exportable (§118).`,
  };
}

/** Period bucket helpers for aggregation (§43). */
export function periodStart(date: Date, granularity: "HOURLY" | "DAILY" | "BILLING_PERIOD", periodAnchor?: Date): Date {
  const d = new Date(date);
  if (granularity === "HOURLY") { d.setUTCMinutes(0, 0, 0); return d; }
  if (granularity === "DAILY") { d.setUTCHours(0, 0, 0, 0); return d; }
  // BILLING_PERIOD: anchored monthly period starting at the anchor's day.
  const anchor = periodAnchor ?? new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1));
  const start = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), anchor.getUTCDate()));
  if (d < start) start.setUTCMonth(start.getUTCMonth() - 1);
  return start;
}

/** Sum usage events into aggregate quantities (§43/§44). */
export function aggregateUsage(
  events: Array<{ metric: string; quantity: number; occurredAt: Date }>,
  granularity: "HOURLY" | "DAILY" | "BILLING_PERIOD",
): Array<{ metric: string; periodStart: Date; quantity: number }> {
  const buckets = new Map<string, { metric: string; periodStart: Date; quantity: number }>();
  for (const e of events) {
    const start = periodStart(e.occurredAt, granularity);
    const key = `${e.metric}|${start.toISOString()}`;
    const bucket = buckets.get(key) ?? { metric: e.metric, periodStart: start, quantity: 0 };
    bucket.quantity += e.quantity;
    buckets.set(key, bucket);
  }
  return [...buckets.values()].sort((a, b) => a.periodStart.getTime() - b.periodStart.getTime());
}
