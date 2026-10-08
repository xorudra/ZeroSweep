import { minCronIntervalMinutes } from "./cron";
import { classifyProfile } from "./safety";

/**
 * Schedule frequency guardrail (Prompt 22 §13). Prevents scheduling
 * expensive scans excessively, based on scan type (profile cost
 * class), target count, tool weight and the workspace quota. The
 * guardrail runs at schedule CREATION and again at fire time — quota
 * state can change between the two.
 */

export type ProfileCostClass = "LIGHT" | "STANDARD" | "HEAVY";

const HEAVY_PROFILES = new Set([
  "SOURCE_COMPREHENSIVE", "CONTAINER_COMPREHENSIVE", "KUBERNETES_COMPREHENSIVE",
  "CLOUD_COMPREHENSIVE", "AD_COMPREHENSIVE", "BINARY_COMPREHENSIVE_STATIC",
  "MOBILE_STATIC_COMPREHENSIVE", "WIRELESS_PASSIVE_COMPREHENSIVE", "CLOUD_NATIVE_FULL",
]);
const LIGHT_PROFILES = new Set([
  "PASSIVE_RECON", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SBOM_ONLY",
  "IMAGE_VULNERABILITIES_ONLY", "BINARY_METADATA_ONLY", "PCAP_ANALYSIS_ONLY",
  "CLOUD_INVENTORY", "AD_INVENTORY", "MOBILE_SECRETS_ONLY",
]);

export function profileCostClass(profile: string): ProfileCostClass {
  if (HEAVY_PROFILES.has(profile)) return "HEAVY";
  if (LIGHT_PROFILES.has(profile)) return "LIGHT";
  return "STANDARD";
}

/** Minimum minutes between runs of one schedule, before target-count
 *  and quota adjustments. */
const BASE_MIN_INTERVAL_MINUTES: Record<ProfileCostClass, number> = {
  LIGHT: 60,
  STANDARD: 360,
  HEAVY: 1440,
};

export interface FrequencyEvaluationInput {
  profile: string;
  expression: string;
  timezone: string;
  targetCount: number;
  /** Runs of this schedule already materialized today (workspace quota). */
  runsTodayForWorkspace: number;
  dailyRunBudget: number;
}

export interface FrequencyEvaluation {
  allowed: boolean;
  costClass: ProfileCostClass;
  requiredMinIntervalMinutes: number;
  actualMinIntervalMinutes: number | null;
  reasonCode: "OK" | "INTERVAL_TOO_SHORT" | "DAILY_BUDGET_EXHAUSTED" | "PROFILE_NOT_SCHEDULABLE" | "INVALID_EXPRESSION";
  message: string;
}

export function evaluateFrequency(input: FrequencyEvaluationInput): FrequencyEvaluation {
  const classification = classifyProfile(input.profile);
  const costClass = profileCostClass(input.profile);
  if (!classification.schedulable) {
    return {
      allowed: false, costClass, requiredMinIntervalMinutes: 0, actualMinIntervalMinutes: null,
      reasonCode: "PROFILE_NOT_SCHEDULABLE",
      message: `profile ${input.profile} is ${classification.safetyClass}: ${classification.reason}`,
    };
  }
  let actual: number | null;
  try {
    actual = minCronIntervalMinutes(input.expression, input.timezone);
  } catch (e) {
    return {
      allowed: false, costClass, requiredMinIntervalMinutes: 0, actualMinIntervalMinutes: null,
      reasonCode: "INVALID_EXPRESSION",
      message: e instanceof Error ? e.message : "invalid cron expression",
    };
  }
  let required = BASE_MIN_INTERVAL_MINUTES[costClass];
  // Large target sets are more expensive — widen the floor (§13).
  if (input.targetCount > 100) required = Math.max(required, 1440);
  else if (input.targetCount > 25) required = Math.max(required, 720);
  if (actual !== null && actual < required) {
    return {
      allowed: false, costClass, requiredMinIntervalMinutes: required, actualMinIntervalMinutes: actual,
      reasonCode: "INTERVAL_TOO_SHORT",
      message: `schedule fires as often as every ${actual} minutes; ${costClass} profiles with ${input.targetCount} target(s) require at least ${required} minutes between runs (§13)`,
    };
  }
  if (input.runsTodayForWorkspace >= input.dailyRunBudget) {
    return {
      allowed: false, costClass, requiredMinIntervalMinutes: required, actualMinIntervalMinutes: actual,
      reasonCode: "DAILY_BUDGET_EXHAUSTED",
      message: `workspace daily scheduled-run budget (${input.dailyRunBudget}) is exhausted (§13)`,
    };
  }
  return {
    allowed: true, costClass, requiredMinIntervalMinutes: required, actualMinIntervalMinutes: actual,
    reasonCode: "OK",
    message: "frequency within policy",
  };
}
