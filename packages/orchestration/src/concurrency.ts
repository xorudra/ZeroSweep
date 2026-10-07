/**
 * Concurrency + rate-limit model (Prompt 4 §24–§25, Prompt 3 §32–§33).
 * Limits exist at global / organization / workspace / scan / tool / worker
 * level so one tenant can never exhaust the platform. Assessment profiles may
 * LOWER limits; they can never raise them above administrator maximums.
 */

export interface ConcurrencyLimits {
  global: number;
  perOrganization: number;
  perWorkspace: number;
  perScan: number;
  perTool: number;
  perWorker: number;
}

export const DEFAULT_CONCURRENCY_LIMITS: ConcurrencyLimits = {
  global: 32,
  perOrganization: 8,
  perWorkspace: 4,
  perScan: 4,
  perTool: 2,
  perWorker: 4,
};

/** Clamp a requested limit into [1, adminMax] — requests can only lower. */
export function clampLimit(requested: number | undefined, adminMax: number): number {
  if (requested === undefined || !Number.isFinite(requested)) return adminMax;
  return Math.max(1, Math.min(adminMax, Math.floor(requested)));
}

/**
 * Counting semaphore keyed by dimension. In-process in this phase (single
 * worker deployments); the same keys map onto Redis counters when workers
 * scale out — call sites do not change.
 */
export class ConcurrencyLimiter {
  private readonly counts = new Map<string, number>();

  constructor(private readonly limits: ConcurrencyLimits = DEFAULT_CONCURRENCY_LIMITS) {}

  tryAcquire(key: string, limit: number): boolean {
    const current = this.counts.get(key) ?? 0;
    if (current >= limit) return false;
    this.counts.set(key, current + 1);
    return true;
  }

  release(key: string): void {
    const current = this.counts.get(key) ?? 0;
    if (current <= 1) this.counts.delete(key);
    else this.counts.set(key, current - 1);
  }

  current(key: string): number {
    return this.counts.get(key) ?? 0;
  }

  /** Acquire every dimension or none (atomic check across the key set). */
  tryAcquireAll(keys: { key: string; limit: number }[]): boolean {
    for (const { key, limit } of keys) {
      if ((this.counts.get(key) ?? 0) >= limit) return false;
    }
    for (const { key } of keys) this.counts.set(key, (this.counts.get(key) ?? 0) + 1);
    return true;
  }

  releaseAll(keys: string[]): void {
    for (const key of keys) this.release(key);
  }
}

export function limitKeys(input: { organizationId: string; workspaceId: string; scanId: string; toolSlug: string; workerId: string }, limits: ConcurrencyLimits): { key: string; limit: number }[] {
  return [
    { key: "global", limit: limits.global },
    { key: `org:${input.organizationId}`, limit: limits.perOrganization },
    { key: `ws:${input.workspaceId}`, limit: limits.perWorkspace },
    { key: `scan:${input.scanId}`, limit: limits.perScan },
    { key: `tool:${input.toolSlug}`, limit: limits.perTool },
    { key: `worker:${input.workerId}`, limit: limits.perWorker },
  ];
}
