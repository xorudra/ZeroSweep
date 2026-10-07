/**
 * Worker heartbeat health + restart recovery (Prompt 4 §21–§23, §51).
 * A single missed heartbeat never marks a worker offline — staleness is
 * judged against configurable thresholds. On restart, stale RUNNING work is
 * reconciled: completed executions are never blindly re-run.
 */

export const WORKER_STATUSES = ["ONLINE", "BUSY", "DEGRADED", "OFFLINE", "DRAINING"] as const;
export type WorkerStatus = (typeof WORKER_STATUSES)[number];

export interface HeartbeatThresholds {
  /** Younger than this (with capacity) = healthy. */
  degradedAfterMs: number;
  /** Older than this = offline. */
  offlineAfterMs: number;
}

export const DEFAULT_HEARTBEAT_THRESHOLDS: HeartbeatThresholds = {
  degradedAfterMs: 30_000,
  offlineAfterMs: 90_000,
};

export function workerStatusFromHeartbeat(input: {
  lastHeartbeatAt: Date | string;
  now: Date;
  activeJobs: number;
  capacity: number;
  draining?: boolean;
  thresholds?: HeartbeatThresholds;
}): WorkerStatus {
  if (input.draining) return "DRAINING";
  const t = input.thresholds ?? DEFAULT_HEARTBEAT_THRESHOLDS;
  const age = input.now.getTime() - new Date(input.lastHeartbeatAt).getTime();
  if (age > t.offlineAfterMs) return "OFFLINE";
  if (age > t.degradedAfterMs) return "DEGRADED";
  if (input.activeJobs >= input.capacity) return "BUSY";
  if (input.activeJobs > 0) return "BUSY";
  return "ONLINE";
}

/** A worker only receives stages whose required capabilities it advertises (§23). */
export function workerCanRun(workerCapabilities: string[], requiredCapabilities: string[]): boolean {
  return requiredCapabilities.every((cap) => workerCapabilities.includes(cap));
}

export type RecoveryAction = "LEAVE" | "REQUEUE" | "MARK_FAILED" | "MARK_TIMED_OUT";

export interface StaleExecution {
  id: string;
  status: string;
  workerId?: string | null;
  workerLastHeartbeatAt?: Date | string | null;
  startedAt?: Date | string | null;
  timeoutSeconds?: number | null;
}

/**
 * Decide what to do with executions left mid-flight by a restart. Completed
 * work is left alone; work on a live worker is left alone; work whose worker
 * is gone is requeued once if it never started, otherwise failed honestly.
 */
export function reconcileStaleExecution(exec: StaleExecution, now: Date, thresholds: HeartbeatThresholds = DEFAULT_HEARTBEAT_THRESHOLDS): RecoveryAction {
  if (["COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED"].includes(exec.status)) return "LEAVE";
  if (exec.status === "QUEUED" || exec.status === "PREPARING") return "REQUEUE";
  if (exec.status === "RUNNING" || exec.status === "PARSING" || exec.status === "NORMALIZING") {
    if (exec.startedAt && exec.timeoutSeconds) {
      const elapsed = now.getTime() - new Date(exec.startedAt).getTime();
      if (elapsed > exec.timeoutSeconds * 1000) return "MARK_TIMED_OUT";
    }
    if (exec.workerLastHeartbeatAt) {
      const age = now.getTime() - new Date(exec.workerLastHeartbeatAt).getTime();
      return age > thresholds.offlineAfterMs ? "MARK_FAILED" : "LEAVE";
    }
    return "MARK_FAILED";
  }
  return "LEAVE";
}
