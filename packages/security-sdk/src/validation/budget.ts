import { ADMIN_HARD_LIMITS, DEFAULT_VALIDATION_BUDGET, type ValidationBudget } from "./types";

/**
 * Validation budgets, administrator hard limits and rate limiting
 * (Prompt 16 §40–§42, §44, §88). Budgets are enforced by the worker
 * while a validator runs: exceeding any dimension terminates the
 * session safely. The dead-man timeout (§44) is the budget's duration
 * dimension — a validation process can never run indefinitely.
 */

/** Clamp a requested budget to the workspace default and then to the
 *  administrator hard limits (§41): every dimension takes the MINIMUM,
 *  so no layer can widen what a stricter layer set. */
export function clampValidationBudget(
  requested: Partial<ValidationBudget> | undefined,
  workspaceDefault: ValidationBudget = DEFAULT_VALIDATION_BUDGET,
  hardLimits: ValidationBudget = ADMIN_HARD_LIMITS,
): ValidationBudget {
  const merged: ValidationBudget = { ...workspaceDefault, ...(requested ?? {}) };
  const out = {} as ValidationBudget;
  (Object.keys(ADMIN_HARD_LIMITS) as (keyof ValidationBudget)[]).forEach((key) => {
    const v = Math.floor(merged[key]);
    out[key] = Math.max(1, Math.min(Number.isFinite(v) ? v : workspaceDefault[key], hardLimits[key]));
  });
  return out;
}

export class BudgetExceededError extends Error {
  constructor(readonly dimension: keyof ValidationBudget, message: string) {
    super(message);
    this.name = "BudgetExceededError";
  }
}

export interface BudgetConsumption {
  requests: number;
  bytes: number;
  redirects: number;
  endpoints: number;
  targets: number;
  elapsedSeconds: number;
}

/** Live budget tracker used by validators through the transport (§88).
 *  `now` is injectable so tests are deterministic. */
export class ValidationBudgetTracker {
  private requests = 0;
  private bytes = 0;
  private redirects = 0;
  private readonly endpoints = new Set<string>();
  private readonly targets = new Set<string>();
  private readonly startedAt: number;

  constructor(
    private readonly budget: ValidationBudget,
    private readonly now: () => number = () => Date.now(),
  ) {
    this.startedAt = this.now();
  }

  consumeRequest(endpoint?: string): void {
    this.checkDuration();
    this.requests += 1;
    if (this.requests > this.budget.maxRequests) {
      throw new BudgetExceededError("maxRequests", `validation budget exceeded: more than ${this.budget.maxRequests} requests (§88)`);
    }
    if (endpoint) {
      this.endpoints.add(endpoint);
      if (this.endpoints.size > this.budget.maxEndpoints) {
        throw new BudgetExceededError("maxEndpoints", `validation budget exceeded: more than ${this.budget.maxEndpoints} endpoints (§88)`);
      }
    }
  }

  consumeBytes(n: number): void {
    this.bytes += n;
    if (this.bytes > this.budget.maxBytes) {
      throw new BudgetExceededError("maxBytes", `validation budget exceeded: more than ${this.budget.maxBytes} bytes transferred (§88)`);
    }
  }

  consumeRedirect(): void {
    this.redirects += 1;
    if (this.redirects > this.budget.maxRedirects) {
      throw new BudgetExceededError("maxRedirects", `validation budget exceeded: more than ${this.budget.maxRedirects} redirects (§88)`);
    }
  }

  consumeTarget(target: string): void {
    this.targets.add(target);
    if (this.targets.size > this.budget.maxTargets) {
      throw new BudgetExceededError("maxTargets", `validation budget exceeded: more than ${this.budget.maxTargets} targets (§88)`);
    }
  }

  /** §44 dead-man check: throws once the hard duration has elapsed. */
  checkDuration(): void {
    const elapsed = (this.now() - this.startedAt) / 1000;
    if (elapsed > this.budget.maxDurationSeconds) {
      throw new BudgetExceededError("maxDurationSeconds", `validation dead-man timeout: exceeded ${this.budget.maxDurationSeconds}s hard limit (§44)`);
    }
  }

  consumption(): BudgetConsumption {
    return {
      requests: this.requests,
      bytes: this.bytes,
      redirects: this.redirects,
      endpoints: this.endpoints.size,
      targets: this.targets.size,
      elapsedSeconds: Math.max(0, (this.now() - this.startedAt) / 1000),
    };
  }
}

/** §42: rate limits apply per organization, workspace, target, validator
 *  and worker. Sliding-window, in-memory, deterministic with an injected
 *  clock — the deployment can back this with Redis without changing the
 *  contract. */
export class ValidationRateLimiter {
  private readonly windows = new Map<string, number[]>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  check(dimension: string, key: string, limit: number, windowSeconds: number): { allowed: boolean; retryAfterSeconds?: number } {
    const nowMs = this.now();
    const bucketKey = `${dimension}:${key}`;
    const cutoff = nowMs - windowSeconds * 1000;
    const hits = (this.windows.get(bucketKey) ?? []).filter((t) => t > cutoff);
    if (hits.length >= limit) {
      const oldest = hits[0]!;
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((oldest + windowSeconds * 1000 - nowMs) / 1000)) };
    }
    hits.push(nowMs);
    this.windows.set(bucketKey, hits);
    return { allowed: true };
  }
}

/** Default per-dimension validation rate limits (§42). */
export const VALIDATION_RATE_LIMITS = {
  organization: { limit: 120, windowSeconds: 3600 },
  workspace: { limit: 60, windowSeconds: 3600 },
  target: { limit: 30, windowSeconds: 3600 },
  validator: { limit: 60, windowSeconds: 3600 },
  worker: { limit: 60, windowSeconds: 3600 },
} as const;
