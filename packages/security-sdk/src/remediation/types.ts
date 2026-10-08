/**
 * Remediation orchestration vocabulary (Prompt 31 §5/§11/§16/§18/§26/
 * §28/§36/§39/§53/§58/§78). These are the canonical string contracts
 * shared by the API module, the worker and the GUI. The central
 * invariant of the whole phase: REMEDIATION_CLAIMED, VERIFICATION_PENDING
 * and VERIFIED_FIXED are different states, and nothing except the
 * verification engine may produce VERIFIED_FIXED (§157).
 */

export const REMEDIATION_STATUSES = [
  "NEW", "TRIAGED", "ASSIGNED", "PLANNED", "IN_PROGRESS", "BLOCKED",
  "FIX_CLAIMED", "VERIFICATION_PENDING", "VERIFICATION_RUNNING",
  "VERIFIED_FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE", "DEFERRED",
  "CLOSED", "REOPENED",
] as const;
export type RemediationStatus = (typeof REMEDIATION_STATUSES)[number];

/** Statuses in which a case still demands work (the "active" set used
 *  for the one-active-case-per-finding rule, §4). */
export const ACTIVE_REMEDIATION_STATUSES: RemediationStatus[] = [
  "NEW", "TRIAGED", "ASSIGNED", "PLANNED", "IN_PROGRESS", "BLOCKED",
  "FIX_CLAIMED", "VERIFICATION_PENDING", "VERIFICATION_RUNNING", "REOPENED",
];

export const TRIAGE_DECISIONS = [
  "ACTION_REQUIRED", "FALSE_POSITIVE", "DUPLICATE",
  "ACCEPT_RISK_CANDIDATE", "NEEDS_MORE_EVIDENCE", "NOT_APPLICABLE",
] as const;
export type TriageDecision = (typeof TRIAGE_DECISIONS)[number];

export const OWNER_TYPES = [
  "USER", "TEAM", "APPLICATION_OWNER", "REPOSITORY_OWNER", "ASSET_OWNER",
] as const;
export type OwnerType = (typeof OWNER_TYPES)[number];

export const OWNERSHIP_CONFIDENCES = ["VERIFIED", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as const;
export type OwnershipConfidence = (typeof OWNERSHIP_CONFIDENCES)[number];

export const SLA_STATES = ["ON_TRACK", "WARNING", "AT_RISK", "BREACHED", "PAUSED", "COMPLETED"] as const;
export type SlaState = (typeof SLA_STATES)[number];

export const SLA_PAUSE_REASONS = [
  "WAITING_VENDOR", "APPROVED_EXCEPTION", "ENVIRONMENT_UNAVAILABLE", "OTHER_APPROVED_REASON",
] as const;
export type SlaPauseReason = (typeof SLA_PAUSE_REASONS)[number];

export const REMEDIATION_OPTIONS = [
  "PATCH", "UPGRADE", "CONFIGURATION_CHANGE", "CODE_FIX",
  "DEPENDENCY_UPDATE", "REMOVE_COMPONENT", "REDUCE_EXPOSURE",
  "COMPENSATING_CONTROL", "OTHER",
] as const;
export type RemediationOption = (typeof REMEDIATION_OPTIONS)[number];

export const PLAN_SOURCES = [
  "PATCH_INTELLIGENCE", "VENDOR_ADVISORY", "SCANNER_RECOMMENDATION", "ANALYST", "APPROVED_GUIDANCE",
] as const;
export type PlanSource = (typeof PLAN_SOURCES)[number];

export const WORK_ITEM_STATUSES = ["PENDING", "CREATED", "SYNCED", "FAILED", "CLOSED", "STALE"] as const;
export type WorkItemStatus = (typeof WORK_ITEM_STATUSES)[number];

export const TICKET_PROVIDERS = ["JIRA", "GITHUB", "GITLAB", "SERVICENOW", "INTERNAL"] as const;
export type TicketProvider = (typeof TICKET_PROVIDERS)[number];

export const FIX_CLAIM_SOURCES = [
  "MANUAL", "TICKET_SYNC", "CI_CD", "REPOSITORY_EVENT", "DEPLOYMENT_EVENT",
] as const;
export type FixClaimSource = (typeof FIX_CLAIM_SOURCES)[number];

export const VERIFICATION_METHODS = [
  "SAFE_RESCAN", "TARGETED_RETEST", "SAST_RESCAN", "SCA_RESCAN",
  "SBOM_REEVALUATION", "CONFIGURATION_RECHECK", "CLOUD_POSTURE_RECHECK",
  "MANUAL_EVIDENCE_REVIEW",
] as const;
export type VerificationMethod = (typeof VERIFICATION_METHODS)[number];

export const VERIFICATION_JOB_STATUSES = [
  "QUEUED", "RUNNING", "PASSED", "FAILED", "INCONCLUSIVE", "ERROR", "CANCELLED",
] as const;
export type VerificationJobStatus = (typeof VERIFICATION_JOB_STATUSES)[number];

/** The outcome of evaluating ONE verification observation (§59–§65). */
export type VerificationOutcome = "PASSED" | "FAILED" | "INCONCLUSIVE" | "ERROR" | "PENDING_CONFIRMATION";

export const EXCEPTION_TYPES = [
  "RISK_ACCEPTANCE", "TEMPORARY_DEFERRAL", "FALSE_POSITIVE_EXCEPTION", "BUSINESS_EXCEPTION",
] as const;
export type RemediationExceptionType = (typeof EXCEPTION_TYPES)[number];

export const REMEDIATION_EVENTS = [
  "REMEDIATION_CASE_CREATED", "REMEDIATION_TRIAGED", "REMEDIATION_ASSIGNED",
  "REMEDIATION_REASSIGNED", "REMEDIATION_PLAN_CREATED", "REMEDIATION_SLA_ASSIGNED",
  "REMEDIATION_SLA_WARNING", "REMEDIATION_SLA_AT_RISK", "REMEDIATION_SLA_PAUSED",
  "REMEDIATION_SLA_BREACHED", "REMEDIATION_TICKET_CREATED", "REMEDIATION_TICKET_SYNCED",
  "REMEDIATION_FIX_CLAIMED", "REMEDIATION_VERIFICATION_REQUESTED",
  "REMEDIATION_VERIFICATION_STARTED", "REMEDIATION_VERIFICATION_PASSED",
  "REMEDIATION_VERIFICATION_FAILED", "REMEDIATION_VERIFICATION_INCONCLUSIVE",
  "REMEDIATION_VERIFIED_FIXED", "REMEDIATION_CLOSED",
  "VULNERABILITY_REGRESSION_DETECTED", "REMEDIATION_EXCEPTION_CREATED",
  "REMEDIATION_EXCEPTION_APPROVED", "REMEDIATION_EXCEPTION_EXPIRED",
  "REMEDIATION_EXCEPTION_EXPIRING", "REMEDIATION_CAMPAIGN_CREATED",
] as const;
export type RemediationEvent = (typeof REMEDIATION_EVENTS)[number];
