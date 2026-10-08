import type { ScanRequestBudget } from "./types";

/**
 * Request budgets + the global safety ceiling (Prompt 32 §48/§126/§127).
 *
 * Every active plan carries a budget. A workspace may tighten a budget
 * freely, but may NEVER raise one past the platform ceiling without a
 * platform-level policy record — the clamp is one-directional and the
 * caller can see exactly which fields were clamped and why.
 */
export const PLATFORM_BUDGET_CEILING: ScanRequestBudget = {
  maxRequests: 100_000,
  maxRequestsPerSecond: 50,
  maxConcurrency: 20,
  maxDurationSeconds: 7_200,
  maxResponseBytes: 5_000_000,
};

/** §124: the default production budget — conservative by construction. */
export const PRODUCTION_DEFAULT_BUDGET: ScanRequestBudget = {
  maxRequests: 10_000,
  maxRequestsPerSecond: 10,
  maxConcurrency: 5,
  maxDurationSeconds: 3_600,
  maxResponseBytes: 2_000_000,
};

/** §125: staging may run broader — still far below the ceiling. */
export const STAGING_DEFAULT_BUDGET: ScanRequestBudget = {
  maxRequests: 50_000,
  maxRequestsPerSecond: 25,
  maxConcurrency: 10,
  maxDurationSeconds: 7_200,
  maxResponseBytes: 5_000_000,
};

export interface BudgetClampResult {
  budget: ScanRequestBudget;
  clampedFields: string[];
}

function clampField(name: keyof ScanRequestBudget, value: number | undefined, ceiling: number, fallback: number, clamped: string[]): number {
  const v = typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
  if (v > ceiling) { clamped.push(name); return ceiling; }
  return v;
}

/** Clamp a requested budget to the platform ceiling (§127). */
export function clampBudget(requested: Partial<ScanRequestBudget> | undefined, base: ScanRequestBudget = PRODUCTION_DEFAULT_BUDGET): BudgetClampResult {
  const clamped: string[] = [];
  const r = requested ?? {};
  return {
    budget: {
      maxRequests: clampField("maxRequests", r.maxRequests, PLATFORM_BUDGET_CEILING.maxRequests, base.maxRequests, clamped),
      maxRequestsPerSecond: clampField("maxRequestsPerSecond", r.maxRequestsPerSecond, PLATFORM_BUDGET_CEILING.maxRequestsPerSecond, base.maxRequestsPerSecond, clamped),
      maxConcurrency: clampField("maxConcurrency", r.maxConcurrency, PLATFORM_BUDGET_CEILING.maxConcurrency, base.maxConcurrency, clamped),
      maxDurationSeconds: clampField("maxDurationSeconds", r.maxDurationSeconds, PLATFORM_BUDGET_CEILING.maxDurationSeconds, base.maxDurationSeconds, clamped),
      maxResponseBytes: clampField("maxResponseBytes", r.maxResponseBytes, PLATFORM_BUDGET_CEILING.maxResponseBytes, base.maxResponseBytes, clamped),
    },
    clampedFields: clamped,
  };
}

/** Coarse request class shown in the plan preview (§11). */
export function requestClassOf(budget: ScanRequestBudget): "SMALL" | "MEDIUM" | "LARGE" {
  if (budget.maxRequests <= 1_000) return "SMALL";
  if (budget.maxRequests <= 25_000) return "MEDIUM";
  return "LARGE";
}

/**
 * §186: a running budget meter. When the request budget is reached the
 * active stages stop gracefully and the scan is COMPLETED_WITH_GAPS —
 * never FAILED, never silently truncated.
 */
export class BudgetMeter {
  private usedRequests = 0;
  private usedResponseBytes = 0;
  constructor(private readonly budget: ScanRequestBudget) {}

  /** Record one request; returns false when the budget is exhausted. */
  recordRequest(responseBytes = 0): boolean {
    if (this.exhausted) return false;
    this.usedRequests += 1;
    this.usedResponseBytes += Math.max(0, responseBytes);
    return true;
  }

  get exhausted(): boolean {
    return this.usedRequests >= this.budget.maxRequests || this.usedResponseBytes >= this.budget.maxResponseBytes;
  }

  get remaining(): number {
    return Math.max(0, this.budget.maxRequests - this.usedRequests);
  }

  snapshot(): { usedRequests: number; usedResponseBytes: number; budget: ScanRequestBudget; exhausted: boolean } {
    return { usedRequests: this.usedRequests, usedResponseBytes: this.usedResponseBytes, budget: this.budget, exhausted: this.exhausted };
  }
}
