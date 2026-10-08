import type { AnalyticsEventInput } from "./events";

/**
 * Finding lifecycle analytics (Prompt 27 §43–§49).
 *
 * The projection is a PURE function of the event history: given the
 * same events it always produces the same projection, which is what
 * makes replay/rebuild deterministic (§133). Events are ordered by
 * eventTime (producer truth, §132) with ingested order as tiebreak —
 * arrival order never rewrites history.
 */

export interface LifecycleProjection {
  findingId: string;
  firstSeenAt: string;
  lastSeenAt: string;
  triagedAt: string | null;
  verifiedAt: string | null;
  resolvedAt: string | null;
  reopenedAt: string | null;
  regressionCount: number;
  /** Seconds from firstSeen to FIRST resolution; null while unresolved (§44 input). */
  remediationSeconds: number | null;
  currentStatus: string;
  severity: string | null;
  cwe: string | null;
  cve: string | null;
  assetId: string | null;
  repositoryId: string | null;
}

interface OrderedEvent extends AnalyticsEventInput { _seq: number }

export function projectFindingLifecycle(events: readonly AnalyticsEventInput[]): LifecycleProjection | null {
  const relevant = events.filter((e) => e.findingId && (
    e.eventType.startsWith("FINDING_") || e.eventType === "KEV_DETECTED" || e.eventType === "EPSS_CHANGED" || e.eventType === "RISK_CHANGED"
  ));
  if (!relevant.length) return null;
  const ordered: OrderedEvent[] = relevant
    .map((e, i) => ({ ...e, _seq: i }))
    .sort((a, b) => (new Date(a.eventTime).getTime() - new Date(b.eventTime).getTime()) || (a._seq - b._seq));

  const first = ordered[0]!;
  const proj: LifecycleProjection = {
    findingId: first.findingId!,
    firstSeenAt: first.eventTime,
    lastSeenAt: ordered[ordered.length - 1]!.eventTime,
    triagedAt: null, verifiedAt: null, resolvedAt: null, reopenedAt: null,
    regressionCount: 0, remediationSeconds: null, currentStatus: "OPEN",
    severity: first.severity ?? null,
    cwe: (first.attributes?.cwe as string) ?? null,
    cve: (first.attributes?.cve as string) ?? null,
    assetId: first.assetId ?? null,
    repositoryId: (first.attributes?.repositoryId as string) ?? null,
  };
  let resolvedOnce = false;
  for (const e of ordered) {
    if (e.severity) proj.severity = e.severity;
    if (e.assetId) proj.assetId = e.assetId;
    const lifecycle = (e.attributes?.lifecycleStatus as string) ?? null;
    switch (e.eventType) {
      case "FINDING_CREATED":
        if (resolvedOnce) { proj.regressionCount++; proj.reopenedAt = e.eventTime; proj.currentStatus = "REOPENED"; }
        else proj.currentStatus = "OPEN";
        break;
      case "FINDING_UPDATED":
        if (lifecycle === "TRIAGED" && !proj.triagedAt) proj.triagedAt = e.eventTime;
        break;
      case "FINDING_VERIFIED":
        if (!proj.verifiedAt) proj.verifiedAt = e.eventTime;
        proj.currentStatus = "CONFIRMED";
        break;
      case "FINDING_RESOLVED":
        if (!resolvedOnce) {
          proj.resolvedAt = e.eventTime;
          proj.remediationSeconds = Math.max(0, Math.round((new Date(e.eventTime).getTime() - new Date(proj.firstSeenAt).getTime()) / 1000));
          resolvedOnce = true;
        }
        proj.currentStatus = "RESOLVED";
        break;
      case "FINDING_REOPENED":
      case "FINDING_REGRESSED":
        if (resolvedOnce) proj.regressionCount++;
        proj.reopenedAt = e.eventTime;
        proj.currentStatus = "REOPENED";
        break;
      default:
        break;
    }
  }
  return proj;
}

/**
 * MTTR (§44). Formula: mean of (first resolution time − first seen
 * time) across findings that HAVE a first resolution, grouped by the
 * requested key. Findings never resolved are excluded from the mean
 * (they have no remediation duration yet) and reported separately as
 * `unresolvedCount`. Empty group → meanSeconds null, never 0.
 */
export interface MttrGroup { key: string; resolvedCount: number; unresolvedCount: number; meanSeconds: number | null; medianSeconds: number | null }

export function mttrBy(projections: readonly LifecycleProjection[], keyOf: (p: LifecycleProjection) => string | null | undefined): MttrGroup[] {
  const groups = new Map<string, { durations: number[]; unresolved: number }>();
  for (const p of projections) {
    const key = keyOf(p);
    if (!key) continue;
    const g = groups.get(key) ?? { durations: [], unresolved: 0 };
    if (p.remediationSeconds != null) g.durations.push(p.remediationSeconds);
    else g.unresolved++;
    groups.set(key, g);
  }
  return [...groups.entries()].map(([key, g]) => {
    const sorted = [...g.durations].sort((a, b) => a - b);
    const mean = sorted.length ? sorted.reduce((s, v) => s + v, 0) / sorted.length : null;
    const median = sorted.length ? sorted[Math.floor((sorted.length - 1) / 2)]! : null;
    return { key, resolvedCount: sorted.length, unresolvedCount: g.unresolved, meanSeconds: mean, medianSeconds: median };
  }).sort((a, b) => (a.key < b.key ? -1 : 1));
}

/** §45/§46: mean time to verify / triage over projections that reached the state. */
export function meanTimeTo(projections: readonly LifecycleProjection[], at: (p: LifecycleProjection) => string | null): number | null {
  const durations: number[] = [];
  for (const p of projections) {
    const t = at(p);
    if (t) durations.push(Math.max(0, (new Date(t).getTime() - new Date(p.firstSeenAt).getTime()) / 1000));
  }
  if (!durations.length) return null;
  return durations.reduce((s, v) => s + v, 0) / durations.length;
}

export interface SlaFinding {
  dueAt: string | null;
  resolvedAt: string | null;
  status: string; // current lifecycle status
}

const RESOLVED = new Set(["RESOLVED", "REMEDIATED", "CLOSED", "FALSE_POSITIVE", "ACCEPTED_RISK"]);

/**
 * SLA analytics (§47). Buckets: WITHIN (due in future beyond the
 * approaching window), APPROACHING (due inside the window),
 * OVERDUE (past due, unresolved, still inside grace), BREACHED (past
 * due by more than the grace window OR resolved after the deadline),
 * MET (resolved on/before the deadline), NO_DEADLINE (no dueAt —
 * counted honestly instead of being silently dropped).
 */
export function slaBuckets(findings: readonly SlaFinding[], now: Date, opts: { approachingHours?: number; graceHours?: number } = {}): Record<string, number> {
  const approachingMs = (opts.approachingHours ?? 72) * 3_600_000;
  const graceMs = (opts.graceHours ?? 0) * 3_600_000;
  const out: Record<string, number> = { WITHIN: 0, APPROACHING: 0, OVERDUE: 0, BREACHED: 0, MET: 0, NO_DEADLINE: 0 };
  for (const f of findings) {
    if (!f.dueAt) { out.NO_DEADLINE!++; continue; }
    const due = new Date(f.dueAt).getTime();
    const resolved = RESOLVED.has(f.status) || f.resolvedAt != null;
    if (resolved) {
      const at = f.resolvedAt ? new Date(f.resolvedAt).getTime() : now.getTime();
      if (at <= due) out.MET!++;
      else out.BREACHED!++;
      continue;
    }
    const remaining = due - now.getTime();
    if (remaining > approachingMs) out.WITHIN!++;
    else if (remaining >= 0) out.APPROACHING!++;
    else if (now.getTime() - due <= graceMs) out.OVERDUE!++;
    else out.BREACHED!++;
  }
  return out;
}

/** §48/§49: most frequent regressions + recurring keys (CWE/CVE/technology/repository/asset). */
export function regressionRanking(projections: readonly LifecycleProjection[], limit = 10): LifecycleProjection[] {
  return [...projections]
    .filter((p) => p.regressionCount > 0)
    .sort((a, b) => b.regressionCount - a.regressionCount || (a.findingId < b.findingId ? -1 : 1))
    .slice(0, limit);
}

export function recurrenceBy(projections: readonly LifecycleProjection[], keyOf: (p: LifecycleProjection) => string | null | undefined, limit = 10): Array<{ key: string; findings: number; regressions: number }> {
  const map = new Map<string, { findings: number; regressions: number }>();
  for (const p of projections) {
    const key = keyOf(p);
    if (!key) continue;
    const g = map.get(key) ?? { findings: 0, regressions: 0 };
    g.findings++;
    g.regressions += p.regressionCount;
    map.set(key, g);
  }
  return [...map.entries()].map(([key, v]) => ({ key, ...v }))
    .sort((a, b) => b.findings - a.findings || b.regressions - a.regressions || (a.key < b.key ? -1 : 1))
    .slice(0, limit);
}
