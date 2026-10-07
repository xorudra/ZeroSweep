/**
 * Controlled security validation domain types (Prompt 16 §3–§5, §12,
 * §33, §36, §40). Validation increases CONFIDENCE in an existing finding
 * through safe, governed rechecks. It is not exploitation: the catalog
 * contains only non-destructive validators, prohibited techniques are
 * classified PROHIBITED_AUTOMATION and can never be planned or executed
 * (§95/§97), and approvals bind to the plan content hash (§10).
 */

export const VALIDATION_RISK_CLASSES = [
  "SAFE",
  "LOW_IMPACT",
  "REVIEW_REQUIRED",
  "INTRUSIVE",
  "PROHIBITED_AUTOMATION",
] as const;
export type ValidationRiskClass = (typeof VALIDATION_RISK_CLASSES)[number];

export const VALIDATION_REQUEST_STATUSES = [
  "REQUESTED",
  "POLICY_REVIEW",
  "APPROVAL_REQUIRED",
  "APPROVED",
  "RUNNING",
  "SUCCEEDED",
  "FAILED",
  "INCONCLUSIVE",
  "BLOCKED",
  "CANCELLED",
  "EXPIRED",
] as const;
export type ValidationRequestStatus = (typeof VALIDATION_REQUEST_STATUSES)[number];

/** §36: validation confidence — deliberately distinct from severity and
 *  from the scanner's own confidence score. */
export const VALIDATION_CONFIDENCES = ["UNVERIFIED", "LIKELY", "VERIFIED", "INCONCLUSIVE"] as const;
export type ValidationConfidence = (typeof VALIDATION_CONFIDENCES)[number];

/** §38: a validation that does not reproduce is NOT automatically a
 *  false positive. These are the only terminal outcome labels. */
export const VALIDATION_OUTCOMES = [
  "REPRODUCED",
  "NOT_REPRODUCED",
  "INCONCLUSIVE",
  "TARGET_CHANGED",
  "VALIDATION_BLOCKED",
  "FIXED",
] as const;
export type ValidationOutcome = (typeof VALIDATION_OUTCOMES)[number];

export const VALIDATION_EVIDENCE_TYPES = [
  "HTTP_REQUEST",
  "HTTP_RESPONSE",
  "TLS_RESULT",
  "SERVICE_RESULT",
  "CONFIGURATION_RESULT",
  "SCREENSHOT",
  "LOG",
  "SCANNER_RESULT",
  "MANUAL_NOTE",
] as const;
export type ValidationEvidenceType = (typeof VALIDATION_EVIDENCE_TYPES)[number];

/** §40: every validation runs under an explicit budget. */
export interface ValidationBudget {
  maxRequests: number;
  maxDurationSeconds: number;
  maxConcurrency: number;
  maxBytes: number;
  maxRedirects: number;
  maxEndpoints: number;
  maxTargets: number;
}

/** §41: administrator hard limits — these override user, workspace, scan
 *  and per-request limits. No request may exceed them, ever. */
export const ADMIN_HARD_LIMITS: ValidationBudget = {
  maxRequests: 200,
  maxDurationSeconds: 900,
  maxConcurrency: 2,
  maxBytes: 10_000_000,
  maxRedirects: 3,
  maxEndpoints: 25,
  maxTargets: 5,
};

/** Conservative defaults (§6/§64): a handful of safe recheck requests. */
export const DEFAULT_VALIDATION_BUDGET: ValidationBudget = {
  maxRequests: 25,
  maxDurationSeconds: 300,
  maxConcurrency: 1,
  maxBytes: 1_000_000,
  maxRedirects: 2,
  maxEndpoints: 5,
  maxTargets: 1,
};

/** The finding shape validators and the policy engine reason about. A
 *  view over the canonical Finding row — never raw scanner output. */
export interface ValidationFindingView {
  id: string;
  title: string;
  fingerprint?: string | null;
  vulnClass?: string | null;
  cwe?: string | null;
  cve?: string | null;
  host?: string | null;
  port?: number | null;
  endpoint?: string | null;
  sources?: string[];
  assetCriticality?: string | null;
  // Domain identities (Prompts 12–15) used by the posture validators.
  repositoryId?: string | null;
  filePath?: string | null;
  ruleId?: string | null;
  componentPurl?: string | null;
  imageDigest?: string | null;
  clusterRef?: string | null;
  cloudProvider?: string | null;
  cloudResourceId?: string | null;
  directoryDomainId?: string | null;
  directoryObjectId?: string | null;
}

/** §13: the validation DAG — fixed stage order for every plan. */
export const VALIDATION_PLAN_STAGES = [
  "AUTHORIZATION",
  "SCOPE_REVALIDATION",
  "POLICY",
  "APPROVAL",
  "BUDGET",
  "SAFE_VALIDATOR",
  "EVIDENCE",
  "CONFIDENCE_UPDATE",
  "REPORT",
] as const;
export type ValidationPlanStage = (typeof VALIDATION_PLAN_STAGES)[number];

export interface ValidationPlan {
  version: 1;
  validatorSlug: string;
  validationType: string;
  riskClass: ValidationRiskClass;
  toolSlug?: string;
  findingId: string;
  targetId: string;
  targetRef: {
    host?: string;
    port?: number;
    endpoint?: string;
    cloudResourceId?: string;
    clusterRef?: string;
    repositoryId?: string;
    imageDigest?: string;
    directoryObjectId?: string;
  };
  /** Allowlisted, per-validator typed parameters ONLY (§79). Raw
   *  commands, payloads, scripts and CLI args are rejected before a plan
   *  can exist (see plan.ts). */
  parameters: Record<string, string | number | boolean>;
  budget: ValidationBudget;
  stages: ValidationPlanStage[];
}

/** §8: immutable authorization snapshot stored with the request. */
export interface ValidationAuthorizationSnapshot {
  targetId: string;
  targetVerified: boolean;
  assessmentId?: string;
  assessmentApproved: boolean;
  authorizationExpiresAt?: string;
  allowedTechniques: string[];
  scopeRules: unknown;
  capturedAt: string;
  capturedBy: string;
}
