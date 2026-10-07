/**
 * Vulnerability lifecycle (Prompt 11 §47–§52). An explicit state machine
 * over the vulnerability-management states; invalid transitions are
 * rejected, never silently coerced (§48). Risk acceptance demands a
 * reason, an authorized approver and an EXPIRY (§49) — permanent silent
 * acceptance does not exist here. False positives demand a reason and a
 * reviewer, and the original finding/evidence is preserved (§51).
 */

export type VmLifecycleStatus =
  | "NEW" | "TRIAGED" | "CONFIRMED" | "IN_PROGRESS" | "REMEDIATED"
  | "RETEST_PENDING" | "RESOLVED" | "FALSE_POSITIVE" | "ACCEPTED_RISK";

export const VM_LIFECYCLE_STATUSES: VmLifecycleStatus[] = [
  "NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED",
  "RETEST_PENDING", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK",
];

/** The transition table (§47/§48). FALSE_POSITIVE and ACCEPTED_RISK are
 *  terminal-ish: leaving them requires reopening to NEW (reclassification)
 *  first — FALSE_POSITIVE → IN_PROGRESS directly is rejected. RESOLVED
 *  leaves only via REOPENED (a failed retest or recurrence, §59), modeled
 *  here as RESOLVED → NEW with a mandatory reason. */
export const VM_TRANSITIONS: Record<VmLifecycleStatus, VmLifecycleStatus[]> = {
  NEW: ["TRIAGED", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK"],
  TRIAGED: ["CONFIRMED", "IN_PROGRESS", "FALSE_POSITIVE", "ACCEPTED_RISK", "NEW"],
  CONFIRMED: ["IN_PROGRESS", "FALSE_POSITIVE", "ACCEPTED_RISK", "REMEDIATED"],
  IN_PROGRESS: ["REMEDIATED", "ACCEPTED_RISK", "FALSE_POSITIVE"],
  REMEDIATED: ["RETEST_PENDING", "RESOLVED", "IN_PROGRESS"],
  RETEST_PENDING: ["RESOLVED", "IN_PROGRESS"], // retest pass → RESOLVED; fail → back to work (REOPENED event)
  RESOLVED: ["NEW"], // recurrence / failed later detection reopens (§59)
  FALSE_POSITIVE: ["NEW"], // reclassification only (§48)
  ACCEPTED_RISK: ["NEW", "TRIAGED"], // expiry returns the finding to the review workflow (§50)
};

export function canTransition(from: VmLifecycleStatus, to: VmLifecycleStatus): boolean {
  return (VM_TRANSITIONS[from] ?? []).includes(to);
}

export interface LifecycleTransitionInput {
  from: VmLifecycleStatus;
  to: VmLifecycleStatus;
  actorId: string;
  reason?: string;
  /** Required for ACCEPTED_RISK (§49): the authorized approver + expiry. */
  riskAcceptance?: { approverId: string; expiresAt: Date };
  /** Required for FALSE_POSITIVE (§51): reviewer identity (the actor). */
  reviewerId?: string;
  now?: Date;
}

export interface LifecycleTransitionResult {
  ok: boolean;
  error?: string;
  /** Side effects the caller must persist (timestamps, acceptance fields). */
  effects: {
    resolvedAt?: Date;
    reopenedAt?: Date;
    recurrenceIncrement?: boolean;
    riskAcceptance?: { reason: string; acceptedBy: string; expiresAt: Date };
    clearRiskAcceptance?: boolean;
  };
}

const REASON_REQUIRED: VmLifecycleStatus[] = ["FALSE_POSITIVE", "ACCEPTED_RISK"];

export function evaluateLifecycleTransition(input: LifecycleTransitionInput): LifecycleTransitionResult {
  const now = input.now ?? new Date();
  const fail = (error: string): LifecycleTransitionResult => ({ ok: false, error, effects: {} });
  if (!VM_LIFECYCLE_STATUSES.includes(input.to)) return fail(`unknown lifecycle status ${input.to}`);
  if (input.from === input.to) return fail(`finding is already ${input.to}`);
  if (!canTransition(input.from, input.to)) {
    return fail(`transition ${input.from} → ${input.to} is not allowed (§48) — reopen/reclassify first if the finding must move`);
  }
  if (REASON_REQUIRED.includes(input.to) && !input.reason?.trim()) {
    return fail(`${input.to} requires a reason (§49/§51)`);
  }
  const effects: LifecycleTransitionResult["effects"] = {};
  if (input.to === "ACCEPTED_RISK") {
    if (!input.riskAcceptance?.approverId) return fail("risk acceptance requires an authorized approver (§49)");
    if (!input.riskAcceptance.expiresAt || Number.isNaN(input.riskAcceptance.expiresAt.getTime())) {
      return fail("risk acceptance requires an expiry date — permanent silent acceptance is not allowed (§49)");
    }
    if (input.riskAcceptance.expiresAt <= now) return fail("risk acceptance expiry must be in the future (§49)");
    effects.riskAcceptance = { reason: input.reason!.trim(), acceptedBy: input.riskAcceptance.approverId, expiresAt: input.riskAcceptance.expiresAt };
  }
  if (input.to === "FALSE_POSITIVE" && !input.reviewerId) {
    return fail("false positive requires a reviewer (§51)");
  }
  if (input.to === "RESOLVED") effects.resolvedAt = now;
  if (input.from === "RESOLVED" && input.to === "NEW") { effects.reopenedAt = now; effects.recurrenceIncrement = true; }
  if (input.from === "ACCEPTED_RISK") effects.clearRiskAcceptance = true;
  return { ok: true, effects };
}

/** §50: an expired acceptance returns the finding to the review workflow. */
export function isRiskAcceptanceExpired(input: { lifecycleStatus: VmLifecycleStatus; riskAcceptanceExpiresAt?: Date | string | null }, now: Date = new Date()): boolean {
  if (input.lifecycleStatus !== "ACCEPTED_RISK" || !input.riskAcceptanceExpiresAt) return false;
  const exp = input.riskAcceptanceExpiresAt instanceof Date ? input.riskAcceptanceExpiresAt : new Date(input.riskAcceptanceExpiresAt);
  return !Number.isNaN(exp.getTime()) && exp <= now;
}

/** Map the VM lifecycle onto the Phase 7 review status so both views of a
 *  finding stay consistent (the findings API predates this layer). */
export function lifecycleToFindingStatus(status: VmLifecycleStatus): "OPEN" | "CONFIRMED" | "ACCEPTED_RISK" | "RESOLVED" | "FALSE_POSITIVE" {
  switch (status) {
    case "CONFIRMED": case "IN_PROGRESS": case "REMEDIATED": case "RETEST_PENDING": return "CONFIRMED";
    case "ACCEPTED_RISK": return "ACCEPTED_RISK";
    case "RESOLVED": return "RESOLVED";
    case "FALSE_POSITIVE": return "FALSE_POSITIVE";
    default: return "OPEN"; // NEW, TRIAGED
  }
}

/** Comment sanitization (§45): comments are analyst text rendered back to
 *  other analysts — strip markup/script carriers, cap length. */
export function sanitizeCommentText(raw: string): string {
  return raw
    .replace(/<[^>]*>/g, "")
    // eslint-disable-next-line no-control-regex -- stripping control chars IS the sanitization
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, "")
    .trim()
    .slice(0, 4000);
}
