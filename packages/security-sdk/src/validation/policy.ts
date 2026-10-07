import { classifyTechnique } from "./catalog";
import type { ValidationRiskClass } from "./types";

/**
 * ValidationPolicyEngine (Prompt 16 §7). Pure and deterministic: given
 * the organization policy, the authorization state, the scope verdict,
 * the finding, the validator's risk class and any approval, it returns
 * ALLOW, DENY or REQUIRE_APPROVAL with a machine-readable reason.
 *
 * Non-negotiables encoded here:
 * - PROHIBITED_AUTOMATION techniques are DENIED unconditionally (§95/§97)
 *   — no approval, lab or policy can allow them.
 * - Automated validation defaults to SAFE only (§5/§64); the production
 *   default policy is SAFE_ONLY.
 * - INTRUSIVE validation is never automated (§63): at most it can be
 *   REQUIRE_APPROVAL inside an explicitly-marked LAB with the intrusive
 *   architecture enabled — and the catalog contains no intrusive
 *   validator, so nothing intrusive can execute regardless.
 * - LAB is never inferred from a hostname (§65) — it arrives as an
 *   explicit environment marker.
 * - High-criticality assets require approval even for LOW_IMPACT (§66).
 * - Separation of duties (§11): requester != approver when required.
 * - Approvals are specific (§10): they bind target + finding + technique
 *   via the plan hash, and expire.
 */

export type ValidationPolicyDecisionType = "ALLOW" | "DENY" | "REQUIRE_APPROVAL";

export type ValidationPolicyReasonCode =
  | "OK"
  | "APPROVED"
  | "PROHIBITED_AUTOMATION"
  | "VALIDATOR_NOT_ALLOWED"
  | "TECHNIQUE_NOT_IN_CATALOG"
  | "TARGET_NOT_VERIFIED"
  | "ASSESSMENT_NOT_APPROVED"
  | "AUTHORIZATION_EXPIRED"
  | "OUT_OF_SCOPE"
  | "SAFE_ONLY_POLICY"
  | "RISK_REQUIRES_APPROVAL"
  | "CRITICALITY_REQUIRES_APPROVAL"
  | "APPROVAL_EXPIRED"
  | "APPROVAL_PLAN_MISMATCH"
  | "APPROVAL_TARGET_MISMATCH"
  | "SEPARATION_OF_DUTIES"
  | "INTRUSIVE_NOT_AUTOMATED";

export interface ValidationPolicyDecision {
  decision: ValidationPolicyDecisionType;
  reasonCode: ValidationPolicyReasonCode;
  message: string;
}

export interface OrganizationValidationPolicy {
  /** §64: production policy. Default SAFE_ONLY. */
  productionPolicy: "SAFE_ONLY" | "SAFE_AND_LOW_IMPACT_WITH_APPROVAL";
  /** §11: requester != approver for higher-risk validations. */
  separationOfDuties: boolean;
  /** §63: intrusive architecture (named approver + short expiry +
   *  isolated LAB) — still never automated execution. */
  allowIntrusiveInLab: boolean;
  /** §77: workspace allowlist of validator slugs; empty = catalog default. */
  allowedValidators: string[];
}

export const DEFAULT_ORGANIZATION_VALIDATION_POLICY: OrganizationValidationPolicy = {
  productionPolicy: "SAFE_ONLY",
  separationOfDuties: true,
  allowIntrusiveInLab: false,
  allowedValidators: [],
};

export interface ValidationApprovalView {
  approverId: string;
  decision: string; // APPROVED | REJECTED
  planHash: string;
  targetId: string;
  findingId: string;
  validatorSlug: string;
  expiresAt: string; // ISO
}

export interface ValidationPolicyInput {
  policy: OrganizationValidationPolicy;
  /** §65: explicit environment marker — never inferred. */
  environment: "PRODUCTION" | "LAB";
  authorization: {
    targetVerified: boolean;
    assessmentApproved: boolean;
    /** ISO expiry of the underlying authorization, when it has one. */
    expiresAt?: string;
  };
  scope: { inScope: boolean; reason?: string };
  assetCriticality?: string | null;
  /** The requested technique: a catalog validator slug, or any other
   *  technique name (classified before it can be planned, §95). */
  technique: string;
  riskClass: ValidationRiskClass;
  requestedBy: string;
  planHash: string;
  targetId: string;
  findingId: string;
  approval?: ValidationApprovalView | null;
  now: Date;
}

const deny = (reasonCode: ValidationPolicyReasonCode, message: string): ValidationPolicyDecision => ({ decision: "DENY", reasonCode, message });
const requireApproval = (reasonCode: ValidationPolicyReasonCode, message: string): ValidationPolicyDecision => ({ decision: "REQUIRE_APPROVAL", reasonCode, message });

function checkApproval(input: ValidationPolicyInput, gateReason: ValidationPolicyReasonCode, gateMessage: string): ValidationPolicyDecision {
  const approval = input.approval;
  if (!approval || approval.decision !== "APPROVED") {
    return requireApproval(gateReason, gateMessage);
  }
  if (new Date(approval.expiresAt).getTime() <= input.now.getTime()) {
    return deny("APPROVAL_EXPIRED", "the approval for this validation has expired — request a fresh approval (§93)");
  }
  if (approval.planHash !== input.planHash) {
    return deny("APPROVAL_PLAN_MISMATCH", "the approval was granted for a different plan — any plan change voids the approval (§10)");
  }
  if (approval.targetId !== input.targetId || approval.findingId !== input.findingId || approval.validatorSlug !== input.technique) {
    return deny("APPROVAL_TARGET_MISMATCH", "approvals are specific to target + finding + validation technique (§10)");
  }
  if (input.policy.separationOfDuties && approval.approverId === input.requestedBy) {
    return deny("SEPARATION_OF_DUTIES", "separation of duties: the requester cannot approve their own higher-risk validation (§11)");
  }
  return { decision: "ALLOW", reasonCode: "APPROVED", message: "valid specific approval on file" };
}

export function evaluateValidationPolicy(input: ValidationPolicyInput): ValidationPolicyDecision {
  // 1. Prohibited automation is denied before anything else is read (§95).
  const classified = classifyTechnique(input.technique);
  if (classified === "PROHIBITED_AUTOMATION" || input.riskClass === "PROHIBITED_AUTOMATION") {
    return deny("PROHIBITED_AUTOMATION", `"${input.technique}" is prohibited automation — it can never be planned, approved or executed by this engine (§97)`);
  }

  // 2. Workspace validator allowlist (§77) and catalog membership (§68):
  //    ToolSelector/policy may only select governed catalog validators.
  if (input.policy.allowedValidators.length > 0 && !input.policy.allowedValidators.includes(input.technique)) {
    return deny("VALIDATOR_NOT_ALLOWED", `validator ${input.technique} is not in the workspace allowlist (§77)`);
  }
  if (classified === "REVIEW_REQUIRED" && input.riskClass === "REVIEW_REQUIRED") {
    return requireApproval("RISK_REQUIRES_APPROVAL", "technique is not a governed catalog validator — human review is required before any validation");
  }

  // 3. Authorization (§8): validation fails when authorization is not
  //    currently valid — verified target + approved assessment + unexpired.
  if (!input.authorization.targetVerified) {
    return deny("TARGET_NOT_VERIFIED", "target ownership is not verified — validation requires a verified target");
  }
  if (!input.authorization.assessmentApproved) {
    return deny("ASSESSMENT_NOT_APPROVED", "the assessment is not approved — validation requires an approved assessment");
  }
  if (input.authorization.expiresAt && new Date(input.authorization.expiresAt).getTime() <= input.now.getTime()) {
    return deny("AUTHORIZATION_EXPIRED", "the authorization snapshot has expired — validation must fail (§8)");
  }

  // 4. Scope (§9): the finding's destination must be in scope NOW.
  if (!input.scope.inScope) {
    return deny("OUT_OF_SCOPE", input.scope.reason ?? "validation destination is outside the approved scope (§85)");
  }

  // 5. Risk gates (§5/§63/§64/§66).
  const risk = input.riskClass;
  if (risk === "INTRUSIVE") {
    if (input.environment === "LAB" && input.policy.allowIntrusiveInLab) {
      return checkApproval(input, "RISK_REQUIRES_APPROVAL", "intrusive validation requires the §63 architecture: explicit authorization, named approver, short expiry, isolated LAB environment");
    }
    return deny("INTRUSIVE_NOT_AUTOMATED", "intrusive validation is not automated by this engine (§63) — use manual validation records (§32)");
  }
  if (risk === "REVIEW_REQUIRED") {
    return checkApproval(input, "RISK_REQUIRES_APPROVAL", "this validation class always requires human approval (§5)");
  }
  if (risk === "LOW_IMPACT") {
    const criticality = (input.assetCriticality ?? "").toUpperCase();
    if (criticality === "CRITICAL" || criticality === "HIGH") {
      return checkApproval(input, "CRITICALITY_REQUIRES_APPROVAL", "high-criticality assets require approval even for LOW_IMPACT validators (§66)");
    }
    if (input.environment === "PRODUCTION" && input.policy.productionPolicy === "SAFE_ONLY") {
      return checkApproval(input, "SAFE_ONLY_POLICY", "production policy is SAFE_ONLY — LOW_IMPACT validation requires approval (§64)");
    }
    return checkApproval(input, "RISK_REQUIRES_APPROVAL", "LOW_IMPACT validation requires approval under the workspace policy");
  }

  // 6. SAFE + verified + approved + in scope → allow (§5/§6).
  return { decision: "ALLOW", reasonCode: "OK", message: "safe validation permitted by policy" };
}
