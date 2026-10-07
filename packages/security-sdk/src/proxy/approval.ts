import { createHash } from "node:crypto";
import type { ScopeRules } from "@dsrclone/validation";

/**
 * Active-scan approval (Prompt 8 §40–§43, §70). ACTIVE_WEB_SCANNING is
 * INTRUSIVE and disabled by default: it becomes eligible only when EVERY
 * precondition holds and a live ScanApproval record covers the capability.
 * Approvals expire, and a material scope change invalidates them — the
 * approval carries a hash of the scope snapshot it was granted against,
 * and any later scope whose hash differs no longer matches (§42/§43).
 * This module is pure decision logic: it never starts anything.
 */

export interface ScanApprovalRecord {
  id: string;
  workspaceId: string;
  assessmentId: string;
  scanId?: string;
  capability: string;
  scannerInstanceId?: string;
  approvedBy: string;
  approvedAt: string;
  expiresAt: string;
  /** Hash of the scope rules snapshot the approval was granted against. */
  scopeSnapshotHash: string;
  scopeId?: string;
  status: "ACTIVE" | "EXPIRED" | "REVOKED" | "INVALIDATED";
  revokedBy?: string;
  revokedAt?: string;
}

/** Deterministic hash of a scope snapshot (§41): canonical key order so
 *  the same rules always hash identically. */
export function hashScopeSnapshot(rules: ScopeRules): string {
  const canonical = JSON.stringify({
    includeHosts: [...rules.includeHosts].sort(),
    excludeHosts: [...rules.excludeHosts].sort(),
    includeCidrs: [...rules.includeCidrs].sort(),
    allowedPorts: [...rules.allowedPorts].sort((a, b) => a - b),
    allowedPaths: [...rules.allowedPaths].sort(),
    excludedPaths: [...rules.excludedPaths].sort(),
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export type ApprovalState =
  | "VALID"
  | "MISSING"
  | "EXPIRED"
  | "REVOKED"
  | "INVALIDATED_SCOPE_CHANGED"
  | "CAPABILITY_MISMATCH";

/** Evaluate an approval record against the CURRENT scope (§42/§43). A
 *  record whose status is still ACTIVE but whose snapshot no longer
 *  matches the live scope evaluates as INVALIDATED_SCOPE_CHANGED — the
 *  stored status is updated by the API layer; the gate never trusts a
 *  stale snapshot. */
export function evaluateApproval(
  approval: ScanApprovalRecord | null | undefined,
  input: { capability: string; currentScopeHash: string; now?: Date },
): { state: ApprovalState; usable: boolean; reason: string } {
  if (!approval) return { state: "MISSING", usable: false, reason: "no approval record exists for this capability" };
  if (approval.status === "REVOKED") return { state: "REVOKED", usable: false, reason: "approval was revoked" };
  if (approval.status === "INVALIDATED") return { state: "INVALIDATED_SCOPE_CHANGED", usable: false, reason: "approval was invalidated by a scope change" };
  const now = input.now ?? new Date();
  if (approval.status === "EXPIRED" || new Date(approval.expiresAt).getTime() <= now.getTime()) {
    return { state: "EXPIRED", usable: false, reason: `approval expired at ${approval.expiresAt}` };
  }
  if (approval.capability !== input.capability) {
    return { state: "CAPABILITY_MISMATCH", usable: false, reason: `approval covers ${approval.capability}, not ${input.capability}` };
  }
  if (approval.scopeSnapshotHash !== input.currentScopeHash) {
    return { state: "INVALIDATED_SCOPE_CHANGED", usable: false, reason: "scope changed after approval — approval invalidated, re-evaluation required (§43)" };
  }
  return { state: "VALID", usable: true, reason: "approval is live and matches the current scope snapshot" };
}

export interface ActiveScanGateInput {
  targetVerified: boolean;
  scopeApproved: boolean;
  assessmentApproved: boolean;
  /** The assessment/profile explicitly enables active testing (§8). */
  activeTestingEnabled: boolean;
  /** The requesting user's role (§12: RBAC permission required). */
  userRole: string;
  /** Administrator policy permits active scanning at all (§8). */
  adminPolicyPermits: boolean;
  approval: ScanApprovalRecord | null | undefined;
  currentScopeHash: string;
  /** Budget with maxActiveScanRequests > 0 (§12/§44). */
  activeBudgetRequests: number;
  now?: Date;
}

export interface ActiveScanGateDecision {
  allowed: boolean;
  /** Machine reason code recorded on denial (audit ACTIVE_SCAN_DENIED). */
  reasonCode: string;
  message: string;
  approvalState?: ApprovalState;
}

const ACTIVE_ROLES = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];

/**
 * The active-scan gate (§8/§12/§40). EVERY condition is required; the
 * first failing condition names the denial. This gate is evaluated before
 * an active stage may be planned for execution — capability metadata or a
 * URL in a form never suffices.
 */
export function evaluateActiveScanGate(input: ActiveScanGateInput): ActiveScanGateDecision {
  if (!input.targetVerified) return { allowed: false, reasonCode: "TARGET_NOT_VERIFIED", message: "Active scanning requires a verified target" };
  if (!input.scopeApproved) return { allowed: false, reasonCode: "SCOPE_NOT_APPROVED", message: "Active scanning requires an approved scope" };
  if (!input.assessmentApproved) return { allowed: false, reasonCode: "ASSESSMENT_NOT_APPROVED", message: "Active scanning requires an approved assessment" };
  if (!input.activeTestingEnabled) return { allowed: false, reasonCode: "ACTIVE_TESTING_NOT_ENABLED", message: "Active testing is not explicitly enabled for this assessment — it is disabled by default (§8)" };
  if (!ACTIVE_ROLES.includes(input.userRole)) return { allowed: false, reasonCode: "ROLE_NOT_PERMITTED", message: `Role ${input.userRole} may not run active scans` };
  if (!input.adminPolicyPermits) return { allowed: false, reasonCode: "ADMIN_POLICY_DENIES", message: "Administrator policy does not permit active scanning" };
  if (!(input.activeBudgetRequests > 0)) return { allowed: false, reasonCode: "NO_ACTIVE_BUDGET", message: "Scan budget allows zero active-scan requests (§44)" };
  const approval = evaluateApproval(input.approval, { capability: "ACTIVE_WEB_SCANNING", currentScopeHash: input.currentScopeHash, ...(input.now ? { now: input.now } : {}) });
  if (!approval.usable) {
    const reasonCode = approval.state === "EXPIRED" ? "APPROVAL_EXPIRED"
      : approval.state === "INVALIDATED_SCOPE_CHANGED" ? "APPROVAL_INVALIDATED_SCOPE_CHANGED"
      : approval.state === "REVOKED" ? "APPROVAL_REVOKED"
      : "APPROVAL_MISSING";
    return { allowed: false, reasonCode, message: `Active scan denied: ${approval.reason}`, approvalState: approval.state };
  }
  return { allowed: true, reasonCode: "APPROVED", message: "Active scan permitted under a live approval", approvalState: "VALID" };
}

/** Pre-scan review summary (§40): exactly what a human confirms before an
 *  approved active scan — assembled from trusted records, never from
 *  free-text input. */
export interface PreScanReview {
  target: string;
  scope: { includeHosts: string[]; excludeHosts: string[]; excludedPaths: string[] };
  scanner: string;
  riskClassification: "INTRUSIVE";
  authenticationProfile: string;
  requestBudget: number;
  rateLimitPerSecond: number;
  estimatedDurationSeconds: number;
  approvalExpiresAt: string;
}

export function buildPreScanReview(input: {
  targetValue: string;
  scope: ScopeRules;
  scannerName: string;
  authenticationProfileName?: string;
  requestBudget: number;
  rateLimitPerSecond: number;
  estimatedDurationSeconds: number;
  approval: ScanApprovalRecord;
}): PreScanReview {
  return {
    target: input.targetValue,
    scope: {
      includeHosts: [...input.scope.includeHosts],
      excludeHosts: [...input.scope.excludeHosts],
      excludedPaths: [...input.scope.excludedPaths],
    },
    scanner: input.scannerName,
    riskClassification: "INTRUSIVE",
    authenticationProfile: input.authenticationProfileName ?? "Anonymous",
    requestBudget: input.requestBudget,
    rateLimitPerSecond: input.rateLimitPerSecond,
    estimatedDurationSeconds: input.estimatedDurationSeconds,
    approvalExpiresAt: input.approval.expiresAt,
  };
}
