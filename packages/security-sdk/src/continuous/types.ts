/**
 * Continuous security monitoring types (Prompt 22 §2–§9).
 *
 * Continuous monitoring does NOT mean unrestricted continuous attacking:
 * only explicitly approved SAFE scan profiles may execute automatically.
 * Intrusive, destructive, credential-attack, exploitation, active
 * wireless, dynamic instrumentation, or other approval-gated operations
 * must NEVER become recurring unattended automation (§122).
 */

export const AUTOMATION_SAFETY_CLASSES = [
  "SAFE_AUTOMATED",
  "APPROVAL_REQUIRED",
  "MANUAL_ONLY",
  "PROHIBITED_AUTOMATION",
] as const;
export type AutomationSafetyClass = (typeof AUTOMATION_SAFETY_CLASSES)[number];

export const SCHEDULE_KINDS = ["SCAN", "REPORT", "REVALIDATION", "INTEL_SYNC", "RETEST"] as const;
export type ScheduleKind = (typeof SCHEDULE_KINDS)[number];

export const SCHEDULE_FREQUENCIES = ["HOURLY", "DAILY", "WEEKLY", "MONTHLY", "CUSTOM"] as const;
export type ScheduleFrequency = (typeof SCHEDULE_FREQUENCIES)[number];

export const MISSED_RUN_POLICIES = ["SKIP", "RUN_ONCE", "CATCH_UP_LIMITED"] as const;
export type MissedRunPolicy = (typeof MISSED_RUN_POLICIES)[number];

/** Hard ceiling for CATCH_UP_LIMITED (§20): never an unlimited backlog. */
export const MAX_CATCH_UP_RUNS = 3;

export const SCHEDULE_RUN_STATUSES = [
  "ENQUEUED", "COMPLETED", "FAILED", "BLOCKED", "SKIPPED", "DEFERRED", "PENDING_APPROVAL",
] as const;
export type ScheduleRunStatus = (typeof SCHEDULE_RUN_STATUSES)[number];

/** Error classes a bounded retry may retry (§21). Policy denials are
 *  deliberately absent — they are NEVER retried. */
export const RETRYABLE_ERROR_CLASSES = [
  "QUEUE_UNAVAILABLE", "WORKER_UNAVAILABLE", "TRANSIENT", "TIMEOUT", "ENQUEUE_FAILED",
] as const;
export const NON_RETRYABLE_ERROR_CLASSES = [
  "POLICY_DENIED", "AUTHORIZATION_EXPIRED", "TARGET_UNVERIFIED", "OUT_OF_SCOPE",
  "SAFETY_CLASS_BLOCKED", "PROHIBITED_AUTOMATION", "VALIDATION_ERROR", "BLACKOUT", "FREQUENCY_DENIED",
] as const;

export interface ScheduleRunKeyParts {
  scheduleId: string;
  /** The scheduled (not actual) fire instant — idempotency is anchored
   *  to the due instant so two scheduler nodes compute the same key. */
  scheduledFor: Date | string;
}

/** Target selector (§5): explicit IDs or governed attribute filters.
 *  Every resolved target must STILL pass authorization at fire time. */
export interface MonitoringTargetSelector {
  assetIds?: string[];
  targetIds?: string[];
  assessmentIds?: string[];
  tags?: string[];
  environment?: string;
  businessUnit?: string;
  assetTypes?: string[];
  criticalities?: string[];
}

export interface MaintenanceWindowDef {
  /** 0 = Sunday … 6 = Saturday, in the window's own timezone. */
  daysOfWeek: number[];
  /** "HH:MM" 24h, window-local. */
  startTime: string;
  endTime: string;
  timezone: string;
  /** ALLOWED_HOURS: runs may only start inside. BLOCKED_HOURS: runs
   *  may never start inside. */
  mode: "ALLOWED_HOURS" | "BLOCKED_HOURS";
}

export interface BlackoutWindowDef {
  startsAt: Date | string;
  endsAt: Date | string;
  reason?: string;
}

export interface SchedulerSettingsView {
  /** Max simultaneously running scheduled scans per workspace (§17/§96). */
  maxConcurrentScheduledScans: number;
  /** Max scheduled runs materialized per workspace per day (§13). */
  dailyRunBudget: number;
  /** Queue depth above which the scheduler defers new work (§95). */
  queueDepthThreshold: number;
  /** Lease TTL for the distributed scheduler lease (§24). */
  leaseTtlSeconds: number;
  /** Max retry attempts for retryable scheduler failures (§21). */
  maxRetryAttempts: number;
}

export const DEFAULT_SCHEDULER_SETTINGS: SchedulerSettingsView = {
  maxConcurrentScheduledScans: 2,
  dailyRunBudget: 200,
  queueDepthThreshold: 100,
  leaseTtlSeconds: 120,
  maxRetryAttempts: 3,
};
