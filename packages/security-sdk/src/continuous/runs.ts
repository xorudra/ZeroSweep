import { createHash } from "node:crypto";
import {
  MAX_CATCH_UP_RUNS, NON_RETRYABLE_ERROR_CLASSES, RETRYABLE_ERROR_CLASSES,
  type MissedRunPolicy, type ScheduleRunKeyParts,
} from "./types";

/**
 * Run identity, missed runs, retries, dedupe, backpressure & fairness
 * (Prompt 22 §18–§21, §95–§96).
 */

/** §19: deterministic idempotency key — two scheduler nodes computing
 *  the key for the same schedule + due instant get the same value, so
 *  the unique constraint turns a race into one execution. */
export function scheduleRunKey(parts: ScheduleRunKeyParts): string {
  const when = new Date(parts.scheduledFor).toISOString();
  return createHash("sha256").update(`schedule-run:${parts.scheduleId}:${when}`).digest("hex");
}

export interface MissedRunDecision {
  action: "NONE" | "RUN_ONCE" | "CATCH_UP";
  /** Number of runs to materialize now. */
  runsToCreate: number;
  /** Due instants that will be skipped (recorded, never silent). */
  skippedInstants: Date[];
}

/**
 * §20: what to do when the scheduler wakes and finds `missed`
 * consecutive due instants. Never creates an unlimited backlog:
 * RUN_ONCE collapses everything into the latest instant;
 * CATCH_UP_LIMITED creates at most MAX_CATCH_UP_RUNS, newest first.
 */
export function decideMissedRuns(policy: MissedRunPolicy, missedInstants: Date[]): MissedRunDecision {
  if (missedInstants.length === 0) return { action: "NONE", runsToCreate: 0, skippedInstants: [] };
  const sorted = [...missedInstants].sort((a, b) => a.getTime() - b.getTime());
  switch (policy) {
    case "SKIP":
      return { action: "NONE", runsToCreate: 0, skippedInstants: sorted };
    case "RUN_ONCE":
      return { action: "RUN_ONCE", runsToCreate: 1, skippedInstants: sorted.slice(0, -1) };
    case "CATCH_UP_LIMITED": {
      const take = Math.min(MAX_CATCH_UP_RUNS, sorted.length);
      return { action: "CATCH_UP", runsToCreate: take, skippedInstants: sorted.slice(0, sorted.length - take) };
    }
  }
}

export interface RetryDecision {
  retry: boolean;
  nextAttemptAt?: Date;
  reason: string;
}

/** §21: bounded retry with exponential backoff. Policy denials are
 *  NEVER retried — retrying a denial would hammer the gate. */
export function decideRetry(input: {
  attempts: number;
  maxAttempts: number;
  errorClass: string;
  now: Date;
  baseBackoffSeconds?: number;
}): RetryDecision {
  if ((NON_RETRYABLE_ERROR_CLASSES as readonly string[]).includes(input.errorClass)) {
    return { retry: false, reason: `${input.errorClass} is a policy/authorization outcome — never retried (§21)` };
  }
  if (!(RETRYABLE_ERROR_CLASSES as readonly string[]).includes(input.errorClass)) {
    return { retry: false, reason: `error class ${input.errorClass} is not classified retryable — fail closed (§21)` };
  }
  if (input.attempts >= input.maxAttempts) {
    return { retry: false, reason: `retry budget exhausted (${input.attempts}/${input.maxAttempts}) — job goes to dead-letter (§22)` };
  }
  const base = input.baseBackoffSeconds ?? 60;
  const backoffSeconds = Math.min(base * 2 ** input.attempts, 3600);
  return {
    retry: true,
    nextAttemptAt: new Date(input.now.getTime() + backoffSeconds * 1000),
    reason: `retryable ${input.errorClass}; attempt ${input.attempts + 1}/${input.maxAttempts} after ${backoffSeconds}s backoff`,
  };
}

/** §18: two scans are equivalent when they target the same assessment
 *  with the same profile — a scheduled run must not duplicate an
 *  equivalent RUNNING scan unless the schedule opts in. */
export interface RunningScanView {
  scanId: string;
  assessmentId: string;
  profile: string;
  status: string;
}

const ACTIVE_SCAN_STATUSES = new Set(["CREATED", "QUEUED", "RUNNING", "IN_PROGRESS", "PAUSED"]);

export function findEquivalentRunningScan(
  running: RunningScanView[],
  candidate: { assessmentId: string; profile: string },
): RunningScanView | undefined {
  return running.find(
    (s) => s.assessmentId === candidate.assessmentId && s.profile === candidate.profile && ACTIVE_SCAN_STATUSES.has(s.status),
  );
}

/** §17: per-workspace / per-target concurrency check for one run. */
export function checkConcurrency(input: {
  runningForWorkspace: number;
  runningForTarget: number;
  maxConcurrentForWorkspace: number;
  maxConcurrentForTarget?: number;
}): { allowed: boolean; reason?: string } {
  if (input.runningForWorkspace >= input.maxConcurrentForWorkspace) {
    return { allowed: false, reason: `workspace concurrency limit reached (${input.runningForWorkspace}/${input.maxConcurrentForWorkspace}) (§17)` };
  }
  const perTarget = input.maxConcurrentForTarget ?? 1;
  if (input.runningForTarget >= perTarget) {
    return { allowed: false, reason: `target concurrency limit reached (${input.runningForTarget}/${perTarget}) (§17)` };
  }
  return { allowed: true };
}

export interface DueScheduleView {
  scheduleId: string;
  workspaceId: string;
  nextRunAt: Date;
}

export interface TickPlan {
  /** Schedules selected to materialize this tick, fairly ordered. */
  selected: DueScheduleView[];
  /** Schedules deferred by backpressure/fairness, with reasons. */
  deferred: Array<{ scheduleId: string; reason: string }>;
}

/**
 * §95/§96: backpressure + tenant fairness for one scheduler tick.
 * When the queue is overloaded the scheduler DEFERS rather than
 * flooding; selection round-robins across workspaces (oldest due
 * first inside each workspace) so a tenant with thousands of due
 * schedules cannot starve a tenant with one (§118).
 */
export function planTick(input: {
  due: DueScheduleView[];
  queueDepth: number;
  queueDepthThreshold: number;
  runningByWorkspace: Record<string, number>;
  maxConcurrentByWorkspace: Record<string, number>;
  maxSelections?: number;
}): TickPlan {
  const deferred: TickPlan["deferred"] = [];
  if (input.queueDepth >= input.queueDepthThreshold) {
    return {
      selected: [],
      deferred: input.due.map((d) => ({
        scheduleId: d.scheduleId,
        reason: `backpressure: queue depth ${input.queueDepth} ≥ threshold ${input.queueDepthThreshold} — deferring instead of flooding (§95)`,
      })),
    };
  }
  const byWorkspace = new Map<string, DueScheduleView[]>();
  for (const d of input.due) {
    const list = byWorkspace.get(d.workspaceId) ?? [];
    list.push(d);
    byWorkspace.set(d.workspaceId, list);
  }
  for (const list of byWorkspace.values()) list.sort((a, b) => a.nextRunAt.getTime() - b.nextRunAt.getTime());
  const selected: DueScheduleView[] = [];
  const running = { ...input.runningByWorkspace };
  const maxSelections = input.maxSelections ?? 50;
  let progressed = true;
  while (progressed && selected.length < maxSelections) {
    progressed = false;
    for (const [workspaceId, list] of byWorkspace) {
      const next = list[0];
      if (!next) continue;
      const limit = input.maxConcurrentByWorkspace[workspaceId] ?? 1;
      if ((running[workspaceId] ?? 0) >= limit) continue;
      selected.push(next);
      list.shift();
      running[workspaceId] = (running[workspaceId] ?? 0) + 1;
      progressed = true;
      if (selected.length >= maxSelections) break;
    }
  }
  for (const list of byWorkspace.values()) {
    for (const d of list) {
      deferred.push({
        scheduleId: d.scheduleId,
        reason: "deferred by fairness/concurrency: workspace slot budget for this tick exhausted (§96)",
      });
    }
  }
  return { selected, deferred };
}
