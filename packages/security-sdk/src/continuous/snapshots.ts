import { createHash } from "node:crypto";

/**
 * Posture / asset / finding snapshots (Prompt 22 §29–§32, §92).
 *
 * Snapshots are IMMUTABLE historical records: they capture the
 * security-relevant state needed for drift + history — never entire
 * raw scanner artifacts (§91). History charts and drift engines read
 * snapshots; nothing ever recomputes history from current state.
 */

export function canonicalHash(value: unknown): string {
  return createHash("sha256").update(stableStringify(value)).digest("hex");
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

export interface AssetSnapshotView {
  /** Stable identity across snapshots: target + host + type. */
  assetKey: string;
  assetId?: string;
  host: string;
  type: string;
  /** Exposure classification as OBSERVED (§36): PRIVATE |
   *  INTERNET_FACING | UNKNOWN — never inferred beyond evidence. */
  exposure: string;
  scopeStatus: string;
  criticality: string;
  ports: number[];
  services: string[];
  endpointCount: number;
}

export interface AssetSnapshotEntry extends AssetSnapshotView {
  stateHash: string;
}

export function buildAssetSnapshotEntry(view: AssetSnapshotView): AssetSnapshotEntry {
  const normalized: AssetSnapshotView = {
    ...view,
    ports: [...new Set(view.ports)].sort((a, b) => a - b),
    services: [...new Set(view.services)].sort(),
  };
  return { ...normalized, stateHash: canonicalHash(normalized) };
}

export function assetKeyOf(input: { targetId: string; host: string; type: string }): string {
  return `${input.targetId}|${input.type}|${input.host.toLowerCase()}`;
}

export interface FindingSnapshotView {
  findingId?: string;
  fingerprint: string;
  status: string;
  lifecycleStatus: string;
  severity: string;
  priority?: string | null;
  riskScore?: number | null;
  verificationStatus: string;
  kevListed: boolean;
  cve?: string | null;
}

export interface FindingSnapshotEntry extends FindingSnapshotView {
  stateHash: string;
}

export function buildFindingSnapshotEntry(view: FindingSnapshotView): FindingSnapshotEntry {
  return { ...view, stateHash: canonicalHash(view) };
}

export interface PostureAggregates {
  assetCount: number;
  findingCount: number;
  findingsBySeverity: Record<string, number>;
  findingsByStatus: Record<string, number>;
  kevCount: number;
  verifiedFindings: number;
  slaOverdue: number;
  slaDueSoon: number;
  /** 0–1 coverage where known; null when unknown — never a fake 100%. */
  coverage: number | null;
  /** Aggregate risk score 0–100 derived from stored scores only. */
  riskScore: number | null;
}

export interface PostureSnapshotData extends PostureAggregates {
  contentHash: string;
}

/** Builds the immutable posture snapshot payload (§29). The risk
 *  score is the mean of stored finding risk scores, rounded — it is
 *  computed from stored values, never invented. */
export function buildPostureSnapshot(input: {
  aggregates: Omit<PostureAggregates, "riskScore">;
  findingRiskScores: number[];
}): PostureSnapshotData {
  const scores = input.findingRiskScores.filter((s) => Number.isFinite(s));
  const riskScore = scores.length === 0 ? null : Math.round((scores.reduce((a, b) => a + b, 0) / scores.length) * 10) / 10;
  const data: PostureAggregates = { ...input.aggregates, riskScore };
  return { ...data, contentHash: canonicalHash(data) };
}

/** §92 rollup: bucket snapshots by hour/day/week, taking the LAST
 *  snapshot per bucket (posture is a state, not a sum) plus counts. */
export function rollupPostureSnapshots<T extends { capturedAt: Date; riskScore: number | null }>(
  snapshots: T[],
  granularity: "HOURLY" | "DAILY" | "WEEKLY",
): Array<{ bucketStart: Date; snapshot: T }> {
  const buckets = new Map<string, { bucketStart: Date; snapshot: T }>();
  const sorted = [...snapshots].sort((a, b) => a.capturedAt.getTime() - b.capturedAt.getTime());
  for (const s of sorted) {
    const d = new Date(s.capturedAt);
    if (granularity === "HOURLY") d.setMinutes(0, 0, 0);
    else if (granularity === "DAILY") d.setHours(0, 0, 0, 0);
    else { d.setHours(0, 0, 0, 0); d.setDate(d.getDate() - ((d.getDay() + 6) % 7)); }
    const key = d.toISOString();
    buckets.set(key, { bucketStart: d, snapshot: s });
  }
  return [...buckets.values()].sort((a, b) => a.bucketStart.getTime() - b.bucketStart.getTime());
}
