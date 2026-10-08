import { createHash } from "node:crypto";
import { getAiTool, type AiRiskClass } from "./gateway";

/**
 * Security AI Planner + deterministic Plan Validator (Prompt 36
 * §41–§50, §74–§78). The planner composes plans ONLY from gateway
 * capabilities and approved scan profiles; the validator is fully
 * deterministic and independent of any LLM (§43) — it re-checks
 * tenant, authorization, scope, permissions, tool availability, risk
 * class, approval, budget, rate limits and platform policy for every
 * step (§44). A plan the validator rejects cannot be executed by any
 * downstream path (§45/§150 fail-closed).
 */

/** §75: AI selects scan profiles from the platform's approved
 *  AssessmentProfile set (packages/types) — it never invents raw
 *  scanner arguments. Intrusiveness is the platform classification
 *  carried from the earlier phases: controlled/dynamic/lab profiles
 *  are HIGH_IMPACT and require explicit approval (§78). */
export const AI_APPROVED_SCAN_PROFILES = [
  "PASSIVE_RECON", "WEB_BASELINE", "WEB_COMPREHENSIVE", "API_ASSESSMENT",
  "NETWORK_DISCOVERY", "NETWORK_BASELINE", "CLOUD_POSTURE", "CONTAINER_BASELINE",
  "MOBILE_STATIC_BASELINE", "BINARY_BASELINE", "WIRELESS_PASSIVE_BASELINE", "AD_BASELINE",
] as const;
export const AI_HIGH_IMPACT_PROFILES = [
  "MOBILE_DYNAMIC_CONTROLLED", "MOBILE_FULL_CONTROLLED", "BINARY_CONTROLLED_DEBUG", "WIRELESS_LAB_VALIDATION",
] as const;
/** §77: the safe default when a user says only "scan this". */
export const AI_SAFE_DEFAULT_PROFILE = "WEB_BASELINE";

export function classifyScanProfile(profile: string): "APPROVED" | "HIGH_IMPACT" | "UNKNOWN" {
  if ((AI_APPROVED_SCAN_PROFILES as readonly string[]).includes(profile)) return "APPROVED";
  if ((AI_HIGH_IMPACT_PROFILES as readonly string[]).includes(profile)) return "HIGH_IMPACT";
  return "UNKNOWN";
}

/** §46: immutable authorization snapshot reference. Plans bind to the
 *  snapshot hash; the snapshot itself is produced by the platform's
 *  authorization/scope engine and AI cannot mutate it mid-run. */
export interface AiAuthorizationSnapshot {
  snapshotId: string;
  workspaceId: string;
  /** Targets covered, with their verification state at snapshot time. */
  targets: { targetId: string; verified: boolean; assessmentApproved: boolean }[];
  scopeHash: string;
  capturedAt: string;
}

export function authorizationSnapshotHash(s: AiAuthorizationSnapshot): string {
  const canonical = JSON.stringify({
    id: s.snapshotId, ws: s.workspaceId, hash: s.scopeHash,
    targets: [...s.targets].sort((a, b) => a.targetId.localeCompare(b.targetId)),
  });
  return createHash("sha256").update(canonical).digest("hex");
}

/** §42: one plan step. */
export interface AiPlanStep {
  id: string;
  objective: string;
  /** Gateway capability name (§27) — never a raw command. */
  capability: string;
  targetReferences: string[];
  dependencies: string[]; // step ids
  riskClass: AiRiskClass;
  requiredPermission: string;
  approvalRequired: boolean;
  expectedEvidence: string[];
  /** For scan steps: the approved profile name (§75). */
  scanProfile?: string;
}

/** §41: the structured plan. */
export interface AiSecurityPlan {
  objective: string;
  taskType: string;
  workspaceId: string;
  authorizationSnapshotHash: string;
  steps: AiPlanStep[];
}

export interface AiPlanValidationContext {
  userPermissions: string[];
  snapshot: AiAuthorizationSnapshot | null;
  /** Tools currently provisioned in the gateway for this workspace. */
  availableTools: string[];
  budgetRemainingTokens: number;
  estimatedPlanTokens: number;
  /** Platform risk ceiling: steps above this class need approval. */
  riskCeilingWithoutApproval: AiRiskClass;
  /** An approval record exists covering this plan (§48). */
  hasApproval: boolean;
}

export interface AiPlanStepFinding {
  stepId: string;
  severity: "REJECT" | "MODIFY";
  reason: string;
  code?: string;
}

export interface AiPlanValidation {
  verdict: "VALID" | "REJECTED" | "REQUIRE_MODIFICATION";
  findings: AiPlanStepFinding[];
  snapshotHashVerified: boolean;
}

const RISK_RANK: Record<AiRiskClass, number> = { NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/** SecurityPlanValidator (§43/§44). Deterministic; no model involved. */
export function validateAiPlan(plan: AiSecurityPlan, ctx: AiPlanValidationContext): AiPlanValidation {
  const findings: AiPlanStepFinding[] = [];
  const reject = (stepId: string, reason: string) => findings.push({ stepId, severity: "REJECT", reason });
  const modify = (stepId: string, reason: string) => findings.push({ stepId, severity: "MODIFY", reason });

  // Tenant + snapshot (§44/§46): plan must bind to the CURRENT
  // immutable snapshot of its own workspace.
  let snapshotHashVerified = false;
  if (!ctx.snapshot) {
    reject("*", "no authorization snapshot available — fail closed (§150)");
  } else if (ctx.snapshot.workspaceId !== plan.workspaceId) {
    reject("*", "authorization snapshot belongs to a different workspace (tenant mismatch, §44)");
  } else if (authorizationSnapshotHash(ctx.snapshot) !== plan.authorizationSnapshotHash) {
    reject("*", "plan authorization snapshot hash does not match the current snapshot — snapshot may have changed since drafting (§46)");
  } else {
    snapshotHashVerified = true;
  }
  const targetById = new Map((ctx.snapshot?.targets ?? []).map((t) => [t.targetId, t]));

  if (ctx.estimatedPlanTokens > ctx.budgetRemainingTokens) {
    reject("*", `plan estimate ${ctx.estimatedPlanTokens} tokens exceeds remaining AI budget ${ctx.budgetRemainingTokens} (§44/§121)`);
  }
  if (plan.steps.length === 0) reject("*", "plan has no steps");

  const stepIds = new Set(plan.steps.map((s) => s.id));
  for (const step of plan.steps) {
    // Tool availability (§44): capability must exist in the gateway
    // catalog AND be provisioned for this workspace.
    const toolDef = getAiTool(step.capability);
    if (!toolDef) { reject(step.id, `capability "${step.capability}" is not in the AI tool gateway catalog (§27)`); continue; }
    if (!ctx.availableTools.includes(step.capability)) reject(step.id, `capability "${step.capability}" is not provisioned for this workspace (§44)`);
    // Permissions (§44).
    if (!ctx.userPermissions.includes(step.requiredPermission)) reject(step.id, `requester lacks permission ${step.requiredPermission} (§44)`);
    if (toolDef.requiredPermission !== step.requiredPermission) {
      modify(step.id, `step permission ${step.requiredPermission} differs from catalog requirement ${toolDef.requiredPermission} — tightened to catalog (§28)`);
    }
    // Scope + authorization (§44): every target reference must be a
    // VERIFIED target on an APPROVED assessment inside the snapshot.
    for (const ref of step.targetReferences) {
      const t = targetById.get(ref);
      if (!t) { reject(step.id, `target ${ref} is not inside the authorization snapshot scope (§44/§107)`); continue; }
      if (!t.verified) reject(step.id, `target ${ref} is not VERIFIED (§44)`);
      if (!t.assessmentApproved) reject(step.id, `target ${ref} has no APPROVED assessment (§44)`);
    }
    // Risk class + approval (§44/§35): above the platform ceiling a
    // step needs approval; approval-required steps need the record.
    if (RISK_RANK[step.riskClass] > RISK_RANK[ctx.riskCeilingWithoutApproval] && !ctx.hasApproval) {
      reject(step.id, `step risk ${step.riskClass} exceeds ceiling ${ctx.riskCeilingWithoutApproval} without an approval record (§44)`);
    }
    if ((step.approvalRequired || toolDef.approvalRequirement === "HUMAN") && !ctx.hasApproval) {
      // §48/§49: an approval-required plan may be CREATED (it then
      // waits in AWAITING_APPROVAL) but can never EXECUTE unapproved.
      // Pending approval is a state, not a rejection.
      findings.push({ stepId: step.id, severity: "MODIFY", reason: "step requires human approval before execution (§48)", code: "APPROVAL_PENDING" });
    }
    // Scan profiles (§75/§78): approved set only; high-impact needs approval.
    if (step.scanProfile) {
      const cls = classifyScanProfile(step.scanProfile);
      if (cls === "UNKNOWN") reject(step.id, `scan profile "${step.scanProfile}" is not an approved platform profile (§75)`);
      if (cls === "HIGH_IMPACT" && !ctx.hasApproval) reject(step.id, `scan profile "${step.scanProfile}" is high-impact and requires explicit approval (§78)`);
    }
    // Dependencies must reference real steps (§42).
    for (const dep of step.dependencies) {
      if (!stepIds.has(dep)) reject(step.id, `dependency "${dep}" does not reference a plan step (§42)`);
      if (dep === step.id) reject(step.id, "step depends on itself (§42)");
    }
  }

  const verdict = findings.some((f) => f.severity === "REJECT") ? "REJECTED"
    : findings.some((f) => f.severity === "MODIFY" && f.code !== "APPROVAL_PENDING") ? "REQUIRE_MODIFICATION" : "VALID";
  return { verdict, findings, snapshotHashVerified };
}

/** §47: workflow states + legal transitions. */
export const AI_WORKFLOW_STATES = [
  "DRAFT", "VALIDATING", "AWAITING_APPROVAL", "APPROVED", "RUNNING",
  "PARTIAL", "COMPLETED", "FAILED", "CANCELLED", "REJECTED",
] as const;
export type AiWorkflowState = (typeof AI_WORKFLOW_STATES)[number];

const TRANSITIONS: Record<AiWorkflowState, AiWorkflowState[]> = {
  DRAFT: ["VALIDATING", "CANCELLED", "REJECTED"],
  VALIDATING: ["AWAITING_APPROVAL", "APPROVED", "REJECTED", "CANCELLED"],
  AWAITING_APPROVAL: ["APPROVED", "REJECTED", "CANCELLED"],
  APPROVED: ["RUNNING", "CANCELLED"],
  RUNNING: ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"],
  PARTIAL: [],
  COMPLETED: [],
  FAILED: [],
  CANCELLED: [],
  REJECTED: [],
};

export function canTransitionWorkflow(from: AiWorkflowState, to: AiWorkflowState): boolean {
  return TRANSITIONS[from]?.includes(to) ?? false;
}

/** §48–§50 + §143: approval evaluation. The approver must be a human
 *  user (§49: AI cannot approve — an approver id of "AI"/"SYSTEM" is
 *  refused), separation of duties applies to restricted actions when
 *  policy requires it (§143), and expired approvals cannot be reused
 *  (§50). */
export function evaluateAiApproval(params: {
  requestedBy: string;
  approverId: string;
  approverIsAi: boolean;
  decision: "APPROVED" | "REJECTED";
  expiresAt: string;
  now: Date;
  separationOfDuties: boolean;
  riskClass: AiRiskClass;
}): { accepted: boolean; reason: string } {
  if (params.approverIsAi || params.approverId === "AI" || params.approverId === "SYSTEM") {
    return { accepted: false, reason: "AI cannot approve an action (§49) — a human approver is required" };
  }
  if (new Date(params.expiresAt).getTime() <= params.now.getTime()) {
    return { accepted: false, reason: "approval window has expired — expired approvals cannot be reused (§50)" };
  }
  if (params.decision === "APPROVED" && params.separationOfDuties && params.requestedBy === params.approverId
    && RISK_RANK[params.riskClass] >= RISK_RANK.HIGH) {
    return { accepted: false, reason: "separation of duties: the requester cannot approve their own HIGH+ risk action (§143)" };
  }
  return { accepted: true, reason: params.decision === "APPROVED" ? "approved by human approver" : "rejected by human approver" };
}
