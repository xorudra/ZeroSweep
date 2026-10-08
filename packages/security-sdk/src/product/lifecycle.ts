/**
 * Organization lifecycle, downgrade & deletion (Prompt 40 §85–§94,
 * §113–§118, §221).
 *
 * Cancellation never silently deletes security history (§88) and never
 * hard-deletes data immediately (§85). Downgrade preserves all data and
 * moves the organization to an OVER_LIMIT state instead (§116/§117):
 * existing data stays readable/exportable while creation of additional
 * over-limit resources is blocked (§118).
 */

export const ORGANIZATION_LIFECYCLE_STATES = [
  "ACTIVE",
  "SUSPENDED",
  "CANCELLATION_PENDING",
  "CANCELLED",
  "RETENTION",
  "DELETION_PENDING",
  "DELETED",
] as const;
export type OrganizationLifecycleState = (typeof ORGANIZATION_LIFECYCLE_STATES)[number];

/** Legal state transitions (§86). DELETED is reachable only via the
 *  controlled deletion workflow (§91–§93), never directly from ACTIVE. */
export const LIFECYCLE_TRANSITIONS: Record<OrganizationLifecycleState, OrganizationLifecycleState[]> = {
  ACTIVE: ["SUSPENDED", "CANCELLATION_PENDING"],
  SUSPENDED: ["ACTIVE", "CANCELLATION_PENDING"],
  CANCELLATION_PENDING: ["ACTIVE", "CANCELLED"],
  CANCELLED: ["RETENTION", "ACTIVE"],
  RETENTION: ["DELETION_PENDING", "ACTIVE"],
  DELETION_PENDING: ["DELETED", "RETENTION"],
  DELETED: [],
};

export function canTransitionLifecycle(from: OrganizationLifecycleState, to: OrganizationLifecycleState): boolean {
  return LIFECYCLE_TRANSITIONS[from]?.includes(to) ?? false;
}

/** Expensive/security actions blocked while suspended (§87). Read,
 *  export and admin recovery stay available in every non-DELETED state. */
export function lifecycleAllowsNewWork(state: OrganizationLifecycleState): boolean {
  return state === "ACTIVE";
}

export interface DowngradeFacts {
  /** dimension -> current usage */
  usage: Record<string, number>;
  /** dimension -> new plan limit (null = unlimited) */
  newLimits: Record<string, number | null>;
  /** features enabled now that the new plan disables */
  disabledFeatures: string[];
  runningScheduledJobs: number;
}

export interface DowngradeImpact {
  overLimitDimensions: Array<{ dimension: string; usage: number; limit: number }>;
  disabledFeatures: string[];
  runningScheduledJobsAffected: number;
  storageOverageBytes: number;
  /** True when the downgrade puts the org into OVER_LIMIT (§117). */
  resultsInOverLimit: boolean;
  /** Downgrade NEVER deletes data (§116). */
  dataDeleted: false;
}

/** §114/§115: downgrade requires this impact preview before applying. */
export function computeDowngradeImpact(facts: DowngradeFacts): DowngradeImpact {
  const overLimitDimensions: Array<{ dimension: string; usage: number; limit: number }> = [];
  for (const [dimension, limit] of Object.entries(facts.newLimits)) {
    if (limit === null || limit === undefined) continue;
    const usage = facts.usage[dimension] ?? 0;
    if (usage > limit) overLimitDimensions.push({ dimension, usage, limit });
  }
  const storage = overLimitDimensions.find((d) => d.dimension === "STORAGE_BYTES");
  return {
    overLimitDimensions,
    disabledFeatures: facts.disabledFeatures,
    runningScheduledJobsAffected: facts.runningScheduledJobs,
    storageOverageBytes: storage ? storage.usage - storage.limit : 0,
    resultsInOverLimit: overLimitDimensions.length > 0,
    dataDeleted: false,
  };
}

export interface DeletionImpact {
  workspaces: number;
  assets: number;
  findings: number;
  reports: number;
  evidenceItems: number;
  integrations: number;
  users: number;
  usageEvents: number;
  /** Legal hold blocks destructive deletion entirely (§94). */
  legalHold: boolean;
  deletionBlocked: boolean;
  blockReason: string | null;
}

/** §92/§94: impact preview computed before any destructive deletion. */
export function computeDeletionImpact(counts: Omit<DeletionImpact, "legalHold" | "deletionBlocked" | "blockReason">, legalHold: boolean): DeletionImpact {
  return {
    ...counts,
    legalHold,
    deletionBlocked: legalHold,
    blockReason: legalHold ? "Organization is under legal hold; destructive deletion is blocked until the hold is released (§94)." : null,
  };
}

/** Default post-cancellation retention window (§89): configurable per deployment. */
export const DEFAULT_RETENTION_DAYS = 90;
