/**
 * SLO / SLI / error budget (Prompt 38 §124–§127). SLIs are computed
 * from REAL persisted operational rows (backup outcomes, restore tests,
 * scan completions). Where no measurement source exists, the result is
 * INSUFFICIENT_DATA — the platform never publishes an availability
 * figure it did not measure (§127/§238).
 */

export type SliKind =
  | "BACKUP_SUCCESS"
  | "RESTORE_TEST_SUCCESS"
  | "SCAN_COMPLETION"
  | "API_AVAILABILITY"
  | "REPORT_GENERATION";

export interface SloDefinition {
  name: string;
  kind: SliKind;
  /** Target success ratio, 0 < target <= 1 (e.g. 0.99). */
  target: number;
  windowDays: number;
}

export interface SliResult {
  kind: SliKind;
  status: "OK" | "BREACHED" | "INSUFFICIENT_DATA";
  /** Measured success ratio; null when there is nothing to measure. */
  ratio: number | null;
  successes: number;
  total: number;
  windowDays: number;
  /** Remaining error budget as a fraction of the allowed budget;
   *  negative once breached; null when unmeasured. */
  errorBudgetRemaining: number | null;
}

export function evaluateSli(
  def: SloDefinition,
  samples: { successes: number; total: number },
): SliResult {
  if (samples.total <= 0 || samples.successes < 0 || samples.successes > samples.total) {
    return {
      kind: def.kind, status: "INSUFFICIENT_DATA", ratio: null,
      successes: Math.max(0, samples.successes), total: Math.max(0, samples.total),
      windowDays: def.windowDays, errorBudgetRemaining: null,
    };
  }
  const ratio = samples.successes / samples.total;
  const allowedFailures = (1 - def.target) * samples.total;
  const failures = samples.total - samples.successes;
  const errorBudgetRemaining = allowedFailures === 0
    ? (failures === 0 ? 1 : -1)
    : (allowedFailures - failures) / allowedFailures;
  return {
    kind: def.kind,
    status: ratio >= def.target ? "OK" : "BREACHED",
    ratio,
    successes: samples.successes,
    total: samples.total,
    windowDays: def.windowDays,
    errorBudgetRemaining,
  };
}

/** Default SLO set. Targets are operator policy, not claims — status is
 *  only ever reported from measured windows (§127). */
export const DEFAULT_SLOS: SloDefinition[] = [
  { name: "Backup success (30d)", kind: "BACKUP_SUCCESS", target: 0.99, windowDays: 30 },
  { name: "Restore test success (90d)", kind: "RESTORE_TEST_SUCCESS", target: 0.95, windowDays: 90 },
  { name: "Scan completion (30d)", kind: "SCAN_COMPLETION", target: 0.95, windowDays: 30 },
];
