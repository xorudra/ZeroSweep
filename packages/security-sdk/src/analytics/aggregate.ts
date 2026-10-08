/**
 * Deterministic aggregation primitives (Prompt 27 §39–§40).
 *
 * Pure functions over rows the caller has already tenant-scoped.
 * Empty input produces EMPTY output (zero buckets only inside an
 * explicitly requested time range — those are real zeros, not
 * synthetic data). No interpolation, ever: a bucket with no records
 * is either absent or a genuine 0 count of records.
 */

export type TimeBucket = "hour" | "day" | "week" | "month";

const BUCKET_MS: Record<TimeBucket, number> = {
  hour: 3_600_000, day: 86_400_000, week: 7 * 86_400_000, month: 30 * 86_400_000,
};

/** Choose a bucket for a range (§40). */
export function bucketForRange(from: Date, to: Date): TimeBucket {
  const span = to.getTime() - from.getTime();
  if (span <= 48 * 3_600_000) return "hour";
  if (span <= 92 * 86_400_000) return "day";
  if (span <= 370 * 86_400_000) return "week";
  return "month";
}

export function bucketStart(d: Date, bucket: TimeBucket): Date {
  const t = new Date(d);
  if (bucket === "hour") t.setMinutes(0, 0, 0);
  else if (bucket === "day") t.setHours(0, 0, 0, 0);
  else if (bucket === "week") { t.setHours(0, 0, 0, 0); t.setDate(t.getDate() - ((t.getDay() + 6) % 7)); }
  else { t.setHours(0, 0, 0, 0); t.setDate(1); }
  return t;
}

export interface TimePoint { bucketStart: string; count: number }

export function timeSeries<T>(rows: readonly T[], timeOf: (r: T) => Date | string | null | undefined, bucket: TimeBucket, range?: { from: Date; to: Date }): TimePoint[] {
  const counts = new Map<number, number>();
  for (const r of rows) {
    const raw = timeOf(r);
    if (raw == null) continue;
    const d = raw instanceof Date ? raw : new Date(raw);
    if (Number.isNaN(d.getTime())) continue;
    const key = bucketStart(d, bucket).getTime();
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  if (!range) {
    return [...counts.entries()].sort((a, b) => a[0] - b[0]).map(([k, count]) => ({ bucketStart: new Date(k).toISOString(), count }));
  }
  const out: TimePoint[] = [];
  const step = BUCKET_MS[bucket];
  const start = bucketStart(range.from, bucket).getTime();
  const end = range.to.getTime();
  // Cap emitted buckets so a hostile range cannot exhaust memory (§148).
  let emitted = 0;
  for (let t = start; t <= end && emitted < 400; t += step, emitted++) {
    out.push({ bucketStart: new Date(t).toISOString(), count: counts.get(t) ?? 0 });
  }
  return out;
}

export function groupCount<T>(rows: readonly T[], keyOf: (r: T) => string | null | undefined): Array<{ key: string; count: number }> {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const k = keyOf(r);
    if (k == null || k === "") continue;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count || (a.key < b.key ? -1 : 1));
}

export function topN<T>(rows: readonly T[], keyOf: (r: T) => string | null | undefined, n: number): Array<{ key: string; count: number }> {
  return groupCount(rows, keyOf).slice(0, Math.max(0, Math.min(n, 100)));
}

export function distribution<T>(rows: readonly T[], keyOf: (r: T) => string | null | undefined): Array<{ key: string; count: number; share: number }> {
  const groups = groupCount(rows, keyOf);
  const total = groups.reduce((s, g) => s + g.count, 0);
  return groups.map((g) => ({ ...g, share: total === 0 ? 0 : g.count / total }));
}

/** Nearest-rank percentile. Empty input → null (never an invented 0). */
export function percentile(values: readonly number[], p: number): number | null {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((Math.min(100, Math.max(0, p)) / 100) * sorted.length);
  return sorted[Math.max(0, rank - 1)] ?? null;
}

export interface TrendResult {
  current: number;
  previous: number;
  delta: number;
  /** null when the previous period is 0 — a percentage would be invented. */
  deltaPct: number | null;
}

/** Period-over-period comparison over REAL counts only (§106 honesty). */
export function trend(current: number, previous: number): TrendResult {
  return {
    current, previous, delta: current - previous,
    deltaPct: previous === 0 ? null : (current - previous) / previous,
  };
}

export function countInRange<T>(rows: readonly T[], timeOf: (r: T) => Date | string | null | undefined, from: Date, to: Date): number {
  let n = 0;
  for (const r of rows) {
    const raw = timeOf(r);
    if (raw == null) continue;
    const t = (raw instanceof Date ? raw : new Date(raw)).getTime();
    if (!Number.isNaN(t) && t >= from.getTime() && t <= to.getTime()) n++;
  }
  return n;
}
