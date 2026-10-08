/**
 * Prompt 37 §115–§120: VulnerabilityMetricsService core.
 *
 * Every metric is computed from stored finding rows + stored state
 * history — never estimated, never reconstructed inaccurately (§75).
 * §117 is explicit and implemented literally: time-to-fix-claim and
 * time-to-verified-closure are DIFFERENT clocks and are reported as
 * separate fields; they are never averaged into a single "MTTR".
 * Any metric whose inputs do not exist is null — not 0, not a guess.
 */
export interface MetricsFindingInput {
  id: string;
  severity: string;
  lifecycleStatus: string;
  kevListed?: boolean;
  createdAt: Date | string;
  /** First entry into a triaged state (from state history), if any. */
  triagedAt?: Date | string | null;
  /** When a fix was first claimed (REMEDIATED / FIX_CLAIMED), if ever. */
  fixClaimedAt?: Date | string | null;
  /** When verified closure happened (Prompt 31 verification PASSED). */
  verifiedClosedAt?: Date | string | null;
  reopenedCount?: number;
  isRegression?: boolean;
  dueAt?: Date | string | null;
  hasActiveRiskAcceptance?: boolean;
}

export interface VulnerabilityMetrics {
  openFindings: number;
  newFindings: number;
  verifiedFixes: number;
  reopenedFindings: number;
  regressions: number;
  /** §117 clock 1: discovery → analyst triage. */
  meanTimeToTriageHours: number | null;
  /** §117 clock 2 (claim): discovery → fix claimed. NOT closure. */
  meanTimeToFixClaimHours: number | null;
  /** §117 clock 3 (verified closure): discovery → verified fixed. */
  meanTimeToVerifiedClosureHours: number | null;
  /** Share of SLA-bound findings not overdue; null when none are bound. */
  slaCompliancePct: number | null;
  riskAcceptanceCount: number;
  falsePositiveRate: number | null;
  kevOpen: number;
  aging: Record<string, number>;
}

export const DEFAULT_AGING_BUCKETS = [
  { key: "0-7", maxDays: 7 },
  { key: "8-30", maxDays: 30 },
  { key: "31-60", maxDays: 60 },
  { key: "61-90", maxDays: 90 },
  { key: "90+", maxDays: Number.POSITIVE_INFINITY },
] as const;

const OPEN = new Set(["NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED", "RETEST_PENDING", "REOPENED", "MITIGATED"]);

function meanHours(pairs: { from: Date; to: Date }[]): number | null {
  if (!pairs.length) return null;
  const total = pairs.reduce((sum, p) => sum + (p.to.getTime() - p.from.getTime()) / 3_600_000, 0);
  return Math.round((total / pairs.length) * 100) / 100;
}

export function computeVulnerabilityMetrics(
  findings: MetricsFindingInput[],
  now: Date,
  periodStart?: Date,
  agingBuckets: readonly { key: string; maxDays: number }[] = DEFAULT_AGING_BUCKETS,
): VulnerabilityMetrics {
  const open = findings.filter((f) => OPEN.has(f.lifecycleStatus));
  const aging: Record<string, number> = Object.fromEntries(agingBuckets.map((b) => [b.key, 0]));
  for (const f of open) {
    const ageDays = (now.getTime() - new Date(f.createdAt).getTime()) / 86_400_000;
    const bucket = agingBuckets.find((b) => ageDays <= b.maxDays) ?? agingBuckets[agingBuckets.length - 1]!;
    aging[bucket.key] = (aging[bucket.key] ?? 0) + 1;
  }
  const slaBound = findings.filter((f) => f.dueAt && OPEN.has(f.lifecycleStatus));
  const slaOk = slaBound.filter((f) => new Date(f.dueAt!).getTime() >= now.getTime());
  const decided = findings.filter((f) => ["CONFIRMED", "FALSE_POSITIVE", "RESOLVED", "ACCEPTED_RISK"].includes(f.lifecycleStatus));
  const fp = findings.filter((f) => f.lifecycleStatus === "FALSE_POSITIVE");
  return {
    openFindings: open.length,
    newFindings: periodStart ? findings.filter((f) => new Date(f.createdAt) >= periodStart).length : findings.length,
    verifiedFixes: findings.filter((f) => f.verifiedClosedAt).length,
    reopenedFindings: findings.filter((f) => (f.reopenedCount ?? 0) > 0 || f.lifecycleStatus === "REOPENED").length,
    regressions: findings.filter((f) => f.isRegression).length,
    meanTimeToTriageHours: meanHours(findings.filter((f) => f.triagedAt).map((f) => ({ from: new Date(f.createdAt), to: new Date(f.triagedAt!) }))),
    meanTimeToFixClaimHours: meanHours(findings.filter((f) => f.fixClaimedAt).map((f) => ({ from: new Date(f.createdAt), to: new Date(f.fixClaimedAt!) }))),
    meanTimeToVerifiedClosureHours: meanHours(findings.filter((f) => f.verifiedClosedAt).map((f) => ({ from: new Date(f.createdAt), to: new Date(f.verifiedClosedAt!) }))),
    slaCompliancePct: slaBound.length ? Math.round((slaOk.length / slaBound.length) * 10000) / 100 : null,
    riskAcceptanceCount: findings.filter((f) => f.hasActiveRiskAcceptance || f.lifecycleStatus === "ACCEPTED_RISK").length,
    falsePositiveRate: decided.length ? Math.round((fp.length / decided.length) * 10000) / 100 : null,
    kevOpen: open.filter((f) => f.kevListed).length,
    aging,
  };
}

/**
 * §120: executive trend series built ONLY from stored metrics
 * snapshots (§119). Points are the snapshots themselves — gaps stay
 * gaps; nothing is interpolated or back-filled from current state.
 */
export interface MetricsSnapshotPoint { capturedAt: string; metrics: VulnerabilityMetrics }
export function executiveTrendSeries(snapshots: MetricsSnapshotPoint[]): {
  capturedAt: string;
  openFindings: number;
  verifiedFixes: number;
  kevOpen: number;
  slaCompliancePct: number | null;
}[] {
  return [...snapshots]
    .sort((a, b) => a.capturedAt.localeCompare(b.capturedAt))
    .map((s) => ({
      capturedAt: s.capturedAt,
      openFindings: s.metrics.openFindings,
      verifiedFixes: s.metrics.verifiedFixes,
      kevOpen: s.metrics.kevOpen,
      slaCompliancePct: s.metrics.slaCompliancePct,
    }));
}
