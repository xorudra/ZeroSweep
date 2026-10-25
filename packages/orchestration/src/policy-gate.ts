import { evaluateToolPolicy, ScopeMatcher, type AuthorizationContext, type PolicyDecision } from "@zerosweep/security-sdk";
import type { ToolMetadata } from "@zerosweep/security-sdk";
import type { ScopeRules } from "@zerosweep/validation";
import type { PlannedStage } from "./plan";

/**
 * Authorization + scope gates (Prompt 4 §11–§12). The plan-time gate decides
 * whether a scan may be queued at all; the execution-time gate is re-run by
 * the worker immediately before every network-capable stage, using trusted
 * state reloaded from the database — never the queued payload.
 */

export interface GateInput {
  auth: AuthorizationContext;
  targetHost: string;
  scopeRules: ScopeRules;
  /** Target row state reloaded from trusted storage. */
  targetExists: boolean;
  targetWorkspaceId: string;
  workspaceId: string;
  targetVerified: boolean;
  assessmentApproved: boolean;
  /** Approval independence (security audit 2026-10-16 run-2): the gate
   *  refuses an APPROVED assessment whose approval was not independent —
   *  approvedBy must be recorded and differ from both the assessment's
   *  creator and the scan requester. Closes the generic scan-start path
   *  that consumed only the APPROVED boolean. */
  assessmentCreatedBy: string;
  assessmentApprovedBy: string | null;
  scopeValid: boolean;
}

export interface GateResult {
  allowed: boolean;
  reasonCode: "OK" | "TARGET_NOT_FOUND" | "WORKSPACE_MISMATCH" | "TARGET_NOT_VERIFIED" | "ASSESSMENT_NOT_APPROVED" | "SCOPE_INVALID" | "TARGET_OUT_OF_SCOPE";
  message: string;
}

export function evaluateAuthorizationGate(input: GateInput): GateResult {
  if (!input.targetExists) return { allowed: false, reasonCode: "TARGET_NOT_FOUND", message: "Target does not exist" };
  if (input.targetWorkspaceId !== input.workspaceId || input.auth.targetOrganizationId !== input.auth.organizationId) {
    return { allowed: false, reasonCode: "WORKSPACE_MISMATCH", message: "Target does not belong to this workspace/organization" };
  }
  if (!input.targetVerified || input.auth.verificationStatus !== "VERIFIED") {
    return { allowed: false, reasonCode: "TARGET_NOT_VERIFIED", message: "Target ownership is not verified" };
  }
  if (!input.assessmentApproved || (input.auth.approvalStatus !== "APPROVED" && input.auth.approvalStatus !== "NOT_REQUIRED")) {
    return { allowed: false, reasonCode: "ASSESSMENT_NOT_APPROVED", message: "Assessment is not approved" };
  }
  if (input.auth.approvalStatus === "APPROVED") {
    const approver = input.assessmentApprovedBy;
    if (!approver || approver === input.assessmentCreatedBy || approver === input.auth.requestedBy) {
      return { allowed: false, reasonCode: "ASSESSMENT_NOT_APPROVED", message: "Assessment approval must be independent: recorded, and granted by someone other than its creator or the scan requester" };
    }
  }
  if (!input.scopeValid) return { allowed: false, reasonCode: "SCOPE_INVALID", message: "Scope rules are invalid" };
  const matcher = new ScopeMatcher(input.scopeRules);
  if (!matcher.isHostAllowed(input.targetHost)) {
    return { allowed: false, reasonCode: "TARGET_OUT_OF_SCOPE", message: "Target host is outside the approved scope" };
  }
  return { allowed: true, reasonCode: "OK", message: "Authorization and scope gates passed" };
}

/** Per-stage, per-adapter policy evaluation at plan time and in the worker. */
export function evaluateStagePolicy(
  stage: PlannedStage,
  tool: ToolMetadata,
  input: {
    auth: AuthorizationContext;
    targetType: string;
    targetHost: string;
    scopeRules: ScopeRules;
    toolEnabled: boolean;
    adapterEnabled: boolean;
    toolHealthy?: boolean;
    availableCredentialRefs?: string[];
    currentConcurrency?: number;
    maxConcurrency?: number;
    /** False when the adapter's network policy cannot reach the target. */
    networkPermitted?: boolean;
  },
): PolicyDecision {
  void stage;
  return evaluateToolPolicy({
    tool,
    toolEnabled: input.toolEnabled,
    adapterEnabled: input.adapterEnabled,
    toolHealthy: input.toolHealthy ?? true,
    targetType: input.targetType,
    targetHost: input.targetHost,
    auth: input.auth,
    scopeRules: input.scopeRules,
    availableCredentialRefs: input.availableCredentialRefs ?? [],
    currentConcurrency: input.currentConcurrency ?? 0,
    maxConcurrency: input.maxConcurrency ?? 4,
    networkPermitted: input.networkPermitted,
  });
}
