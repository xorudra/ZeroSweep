/**
 * Queue operations policy (Prompt 38 §41–§46): bounded retries with
 * backoff + jitter, dead-lettering, priority aging (no indefinite
 * starvation) and job leases with stale-worker detection. Pure
 * functions — the API admin plane and the workers apply the same rules.
 */

export interface RetryPolicy {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffFactor: number;
}

/** Bounded by construction (§42/§244): attempts are capped, delays are
 *  capped, and there is no infinite-retry configuration. */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 5,
  baseDelayMs: 5_000,
  maxDelayMs: 15 * 60_000,
  backoffFactor: 2,
};

export function retryDelayMs(policy: RetryPolicy, attempt: number, jitterSeed = 0.5): number {
  const exp = Math.min(policy.maxDelayMs, policy.baseDelayMs * policy.backoffFactor ** Math.max(0, attempt - 1));
  // Deterministic jitter in [0.5, 1.0) of the exponential delay — the
  // caller passes a random seed in production; tests pass a fixed one.
  const jitter = 0.5 + Math.min(0.999, Math.max(0, jitterSeed)) / 2;
  return Math.round(exp * jitter);
}

export type QueueRetryDecision =
  | { action: "RETRY"; delayMs: number }
  | { action: "DEAD_LETTER"; reason: string };

export function retryDecision(policy: RetryPolicy, attemptsMade: number, jitterSeed?: number): QueueRetryDecision {
  if (attemptsMade >= policy.maxAttempts) {
    return { action: "DEAD_LETTER", reason: `attempts exhausted (${attemptsMade}/${policy.maxAttempts})` };
  }
  return { action: "RETRY", delayMs: retryDelayMs(policy, attemptsMade + 1, jitterSeed) };
}

/**
 * Priority aging (§41): effective priority grows with wait time so a
 * low-priority job is guaranteed to surface; it can never overtake a
 * job that was submitted at the highest base priority.
 */
export function effectivePriority(basePriority: number, waitedMs: number, agingPerMinute = 1): number {
  const aged = basePriority + Math.floor(waitedMs / 60_000) * agingPerMinute;
  return Math.min(aged, 99);
}

/** Job lease (§45/§46): a worker that stops heartbeating loses its job
 *  once the lease expires; the job returns to the queue or fails per
 *  policy — it never silently disappears. */
export interface JobLease {
  workerId: string;
  leasedAt: number;
  heartbeatAt: number;
  leaseMs: number;
}

export function leaseState(lease: JobLease, now: number): "ACTIVE" | "STALE" | "EXPIRED" {
  const sinceBeat = now - lease.heartbeatAt;
  if (sinceBeat <= lease.leaseMs / 2) return "ACTIVE";
  if (sinceBeat <= lease.leaseMs) return "STALE";
  return "EXPIRED";
}

/** Job kinds an operator may safely retry from the admin plane (§198):
 *  every payload is IDs-only, so a retry re-loads governed state from
 *  Postgres and re-runs the full authorization/scope gates in the
 *  worker. Anything else is refused, never improvised. */
export const OPERATOR_RETRYABLE_KINDS = new Set([
  "SCAN_ORCHESTATION",
  "RETEST_EXECUTION",
  "VALIDATION_EXECUTION",
  "INTEGRATION_OUTBOX",
  "ASSESSMENT_ORCHESTRATION_PLACEHOLDER",
]);

export function operatorRetryAllowed(kind: string | undefined): boolean {
  return kind !== undefined && OPERATOR_RETRYABLE_KINDS.has(kind);
}
