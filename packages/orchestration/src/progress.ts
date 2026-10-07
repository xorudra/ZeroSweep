import type { PlannedStage } from "./plan";
import type { StageStatus } from "./state-machines";

/**
 * Weighted progress (Prompt 4 §39) — computed from stage weights and stage
 * completion fractions, never from elapsed time. Progress is monotonic:
 * callers persist the max(previous, computed) so it never moves backward.
 */

const STATUS_FRACTION: Record<StageStatus, number> = {
  PENDING: 0, BLOCKED: 0, READY: 0, QUEUED: 0,
  RUNNING: 0.5, COMPLETED: 1, PARTIAL: 1, FAILED: 1, SKIPPED: 1, CANCELLED: 1,
};

export function computeScanProgress(
  stages: Pick<PlannedStage, "weight">[],
  statusByStage: ReadonlyMap<string, string>,
  stageIds: string[],
): number {
  const totalWeight = stages.reduce((sum, s) => sum + s.weight, 0);
  if (totalWeight === 0) return 0;
  let earned = 0;
  stages.forEach((stage, i) => {
    const status = (statusByStage.get(stageIds[i]!) ?? "PENDING") as StageStatus;
    earned += stage.weight * (STATUS_FRACTION[status] ?? 0);
  });
  return Math.round((earned / totalWeight) * 100);
}

/** Convenience overload keyed by stage type (plan stage ids == types). */
export function progressForPlan(
  stages: PlannedStage[],
  statusByStage: ReadonlyMap<string, string>,
): number {
  return computeScanProgress(stages, statusByStage, stages.map((s) => s.id));
}

export function monotonicProgress(previous: number, next: number): number {
  return Math.max(previous, Math.min(100, Math.max(0, next)));
}

/** Roll stage outcomes up into a final scan status (Prompt 4 §17/§57). */
export function finalScanStatus(statuses: Iterable<string>): "COMPLETED" | "PARTIAL" | "FAILED" {
  const list = [...statuses];
  const failed = list.filter((s) => s === "FAILED").length;
  const partial = list.filter((s) => s === "PARTIAL").length;
  const done = list.filter((s) => s === "COMPLETED").length;
  if (failed > 0) return done > 0 || partial > 0 || list.some((s) => s === "SKIPPED") ? "PARTIAL" : "FAILED";
  if (partial > 0) return "PARTIAL";
  return "COMPLETED";
}
