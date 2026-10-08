import { REMEDIATION_STATUSES, type RemediationStatus } from "./types";

/**
 * Remediation state machine (Prompt 31 §6/§7). Explicit transition
 * table; anything not listed is rejected. VERIFIED_FIXED is reachable
 * ONLY from VERIFICATION_RUNNING (the verification engine drives that
 * edge, §61) and CLOSED only from VERIFIED_FIXED / ACCEPTED_RISK /
 * FALSE_POSITIVE / DEFERRED — so NEW → CLOSED and ticket-driven closure
 * are structurally impossible (§133/§157).
 */
export const REMEDIATION_TRANSITIONS: Record<RemediationStatus, RemediationStatus[]> = {
  NEW: ["TRIAGED", "ASSIGNED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DEFERRED"],
  TRIAGED: ["ASSIGNED", "PLANNED", "IN_PROGRESS", "FALSE_POSITIVE", "ACCEPTED_RISK", "DEFERRED", "NEW"],
  ASSIGNED: ["PLANNED", "IN_PROGRESS", "BLOCKED", "FALSE_POSITIVE", "ACCEPTED_RISK", "DEFERRED", "TRIAGED"],
  PLANNED: ["IN_PROGRESS", "BLOCKED", "DEFERRED", "ASSIGNED"],
  IN_PROGRESS: ["BLOCKED", "FIX_CLAIMED", "DEFERRED", "ASSIGNED"],
  BLOCKED: ["IN_PROGRESS", "ASSIGNED", "DEFERRED"],
  FIX_CLAIMED: ["VERIFICATION_PENDING", "IN_PROGRESS"],
  VERIFICATION_PENDING: ["VERIFICATION_RUNNING", "IN_PROGRESS", "FIX_CLAIMED"],
  VERIFICATION_RUNNING: ["VERIFIED_FIXED", "VERIFICATION_PENDING", "IN_PROGRESS"],
  VERIFIED_FIXED: ["CLOSED", "REOPENED"],
  ACCEPTED_RISK: ["CLOSED", "TRIAGED", "IN_PROGRESS"],
  FALSE_POSITIVE: ["CLOSED", "NEW"],
  DEFERRED: ["TRIAGED", "ASSIGNED", "CLOSED"],
  CLOSED: ["REOPENED"],
  REOPENED: ["TRIAGED", "ASSIGNED", "IN_PROGRESS"],
};

export function canRemediationTransition(from: RemediationStatus, to: RemediationStatus): boolean {
  return (REMEDIATION_TRANSITIONS[from] ?? []).includes(to);
}

export interface RemediationTransitionVerdict {
  ok: boolean;
  error?: string;
}

/**
 * Guarded transitions (§7/§68/§86/§119):
 * - VERIFIED_FIXED requires `viaVerification` (a satisfied verification
 *   policy) — a bare state-set can never mint it.
 * - CLOSED from VERIFIED_FIXED requires `viaClosure` (closure engine
 *   checks satisfied).
 * - FIX_CLAIMED requires a recorded fix claim (`viaFixClaim`).
 * - FALSE_POSITIVE requires reason + evidence (§12).
 * - ACCEPTED_RISK requires an approved exception (`viaException`).
 */
export function evaluateRemediationTransition(input: {
  from: RemediationStatus;
  to: RemediationStatus;
  reason?: string;
  evidence?: unknown;
  viaVerification?: boolean;
  viaClosure?: boolean;
  viaFixClaim?: boolean;
  viaException?: boolean;
}): RemediationTransitionVerdict {
  const fail = (error: string): RemediationTransitionVerdict => ({ ok: false, error });
  if (!REMEDIATION_STATUSES.includes(input.to)) return fail(`unknown remediation status ${input.to}`);
  if (input.from === input.to) return fail(`case is already ${input.to}`);
  if (!canRemediationTransition(input.from, input.to)) {
    return fail(`transition ${input.from} → ${input.to} is not allowed (§7)`);
  }
  if (input.to === "VERIFIED_FIXED" && !input.viaVerification) {
    return fail("VERIFIED_FIXED requires a satisfied verification policy (§61) — claims and ticket states never verify a fix");
  }
  if (input.to === "CLOSED" && input.from === "VERIFIED_FIXED" && !input.viaClosure) {
    return fail("closing a verified case requires the closure engine (§68)");
  }
  if (input.to === "FIX_CLAIMED" && !input.viaFixClaim) {
    return fail("FIX_CLAIMED requires a recorded fix claim (§50)");
  }
  if (input.to === "FALSE_POSITIVE") {
    if (!input.reason?.trim()) return fail("false positive requires a reason (§12)");
    if (input.evidence === undefined || input.evidence === null) return fail("false positive requires evidence (§12)");
  }
  if (input.to === "ACCEPTED_RISK" && !input.viaException) {
    return fail("ACCEPTED_RISK requires an approved remediation exception (§78)");
  }
  return { ok: true };
}

/** Bulk actions (§84): the closed set of safe mass operations. CLOSE is
 *  deliberately absent — mass verified closure without per-case
 *  verification evidence is rejected (§86/§146). */
export const BULK_REMEDIATION_ACTIONS = [
  "ASSIGN", "CREATE_TICKETS", "APPLY_SLA_POLICY", "REQUEST_VERIFICATION",
] as const;
export type BulkRemediationAction = (typeof BULK_REMEDIATION_ACTIONS)[number];
export const BULK_REMEDIATION_MAX_ITEMS = 100;
