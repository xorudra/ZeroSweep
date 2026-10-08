/**
 * Autonomous Security Analysis Engine (Prompt 36 §37–§40, §155–§157).
 * The engine reacts to platform EVENTS by producing ANALYSIS ONLY:
 * dedup assistance, explanations, risk-context summaries, remediation
 * drafts, attack-path CANDIDATE analysis, incident enrichment,
 * executive summaries and trend detection (§39). A trigger can never
 * launch exploitation, scanning or any offensive action (§40/§156) —
 * the mapping below is a closed table, and any event outside it maps
 * to no work at all.
 */

export const AI_ANALYSIS_TRIGGERS = [
  "SCAN_COMPLETED", "FINDING_CREATED", "CRITICAL_FINDING_CREATED",
  "ASSET_EXPOSURE_CHANGED", "KEV_MATCHED", "RUNTIME_SIGNAL_RECEIVED",
  "INCIDENT_CREATED", "REMEDIATION_VERIFICATION_FAILED",
] as const;
export type AiAnalysisTrigger = (typeof AI_ANALYSIS_TRIGGERS)[number];

export const AI_AUTOMATIC_TASKS = [
  "DEDUP_ASSISTANCE", "FINDING_EXPLANATION", "RISK_CONTEXT_SUMMARY",
  "REMEDIATION_DRAFT", "ATTACK_PATH_CANDIDATE_ANALYSIS", "INCIDENT_ENRICHMENT",
  "EXECUTIVE_SUMMARY", "TREND_DETECTION",
] as const;
export type AiAutomaticTask = (typeof AI_AUTOMATIC_TASKS)[number];

const TRIGGER_TASKS: Record<AiAnalysisTrigger, AiAutomaticTask[]> = {
  SCAN_COMPLETED: ["EXECUTIVE_SUMMARY", "TREND_DETECTION"],
  FINDING_CREATED: ["DEDUP_ASSISTANCE", "FINDING_EXPLANATION", "RISK_CONTEXT_SUMMARY"],
  CRITICAL_FINDING_CREATED: ["FINDING_EXPLANATION", "RISK_CONTEXT_SUMMARY", "REMEDIATION_DRAFT", "ATTACK_PATH_CANDIDATE_ANALYSIS"],
  ASSET_EXPOSURE_CHANGED: ["RISK_CONTEXT_SUMMARY", "ATTACK_PATH_CANDIDATE_ANALYSIS"],
  KEV_MATCHED: ["RISK_CONTEXT_SUMMARY", "REMEDIATION_DRAFT"],
  RUNTIME_SIGNAL_RECEIVED: ["INCIDENT_ENRICHMENT"],
  INCIDENT_CREATED: ["INCIDENT_ENRICHMENT", "EXECUTIVE_SUMMARY"],
  REMEDIATION_VERIFICATION_FAILED: ["REMEDIATION_DRAFT", "RISK_CONTEXT_SUMMARY"],
};

export interface AiAnalysisWorkItem {
  trigger: AiAnalysisTrigger;
  tasks: AiAutomaticTask[];
  /** Analysis never executes anything (§40). */
  executed: false;
  /** Offensive follow-through is structurally absent, stated plainly. */
  offensiveAction: "NONE";
}

export function planAutomaticAnalysis(trigger: string): AiAnalysisWorkItem | null {
  if (!(AI_ANALYSIS_TRIGGERS as readonly string[]).includes(trigger)) return null;
  const t = trigger as AiAnalysisTrigger;
  return { trigger: t, tasks: TRIGGER_TASKS[t], executed: false, offensiveAction: "NONE" };
}

/** §155: the optional scheduled daily summaries. §156: producing one
 *  can never expand scope or launch active tests — summaries are
 *  read-only compositions over existing records. */
export const AI_DAILY_SUMMARY_KINDS = [
  "NEW_CRITICAL_FINDINGS", "NEW_KEV_EXPOSURE", "REMEDIATION_OVERDUE", "ATTACK_SURFACE_CHANGE",
] as const;
export type AiDailySummaryKind = (typeof AI_DAILY_SUMMARY_KINDS)[number];
