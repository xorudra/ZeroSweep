/**
 * Prompt 37 §7/§8: the V2 finding lifecycle VIEW.
 *
 * This is a projection, not a second state machine. The authoritative
 * machines remain the Prompt 11 lifecycle (VmLifecycleStatus), the
 * Prompt 20 review verdict (FindingStatus) and the Prompt 31
 * remediation case machine (REMEDIATION_TRANSITIONS). The V2 state of a
 * finding is DERIVED from those records so the portal, dashboards and
 * reports all speak the §7 vocabulary without any code path being able
 * to move a finding outside the governed machines (§10/§153: AI and
 * clients can never write lifecycle state directly — they request
 * transitions that the governed services evaluate).
 */
export const V2_FINDING_LIFECYCLE = [
  "NEW", "TRIAGED", "CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK",
  "REMEDIATION_PLANNED", "IN_PROGRESS", "FIX_CLAIMED",
  "VERIFICATION_PENDING", "FIXED_VERIFIED", "REOPENED", "CLOSED",
] as const;
export type V2FindingLifecycle = (typeof V2_FINDING_LIFECYCLE)[number];

export interface LifecycleProjectionInput {
  /** VmLifecycleStatus (Prompt 11/20). */
  lifecycleStatus: string;
  /** Prompt 31 remediation case status, when a case exists. */
  caseStatus?: string | null;
  /** Prompt 31 case verification outcome, when known. */
  caseVerificationState?: string | null;
  /** FindingVerificationStatus: UNVERIFIED | LIKELY | CONFIRMED | REJECTED. */
  verificationStatus?: string | null;
}

/**
 * Derive the §7 state. Case state wins for the remediation tail
 * (PLANNED → REMEDIATION_PLANNED, FIX_CLAIMED, VERIFIED_FIXED →
 * FIXED_VERIFIED, CLOSED → CLOSED) because Prompt 31 owns that segment;
 * the finding lifecycle owns triage/validation states.
 */
export function toV2LifecycleState(input: LifecycleProjectionInput): V2FindingLifecycle {
  const cs = input.caseStatus ?? null;
  if (cs === "CLOSED") return "CLOSED";
  if (cs === "VERIFIED_FIXED") return "FIXED_VERIFIED";
  if (cs === "FIX_CLAIMED") return "FIX_CLAIMED";
  if (cs === "VERIFICATION_PENDING" || cs === "VERIFICATION_RUNNING") return "VERIFICATION_PENDING";
  if (cs === "PLANNED") return "REMEDIATION_PLANNED";
  if (cs === "IN_PROGRESS" || cs === "REOPENED") {
    // A reopened case whose finding is not REOPENED is mid-remediation.
    if (input.lifecycleStatus !== "REOPENED") return "IN_PROGRESS";
  }
  switch (input.lifecycleStatus) {
    case "NEW": return "NEW";
    case "TRIAGED": return "TRIAGED";
    case "CONFIRMED": return "CONFIRMED";
    case "FALSE_POSITIVE": return "FALSE_POSITIVE";
    case "ACCEPTED_RISK": return "ACCEPTED_RISK";
    case "IN_PROGRESS": return "IN_PROGRESS";
    case "REMEDIATED": return "FIX_CLAIMED"; // fix claimed, awaiting the Prompt 31 verification
    case "RETEST_PENDING": return "VERIFICATION_PENDING";
    case "RESOLVED":
      // Verified closure is only claimed when the verification record
      // actually confirms it; a plain resolution reads as CLOSED (§30).
      return input.caseVerificationState === "PASSED" || input.verificationStatus === "CONFIRMED"
        ? "FIXED_VERIFIED"
        : "CLOSED";
    case "REOPENED": return "REOPENED";
    case "DUPLICATE": return "CLOSED"; // merged into a canonical finding (§47)
    case "MITIGATED": return "IN_PROGRESS"; // risk reduced, remediation not complete
    default: return "NEW";
  }
}

/** §7: states in which a finding still needs work (open exposure). */
export const V2_OPEN_STATES: readonly V2FindingLifecycle[] = [
  "NEW", "TRIAGED", "CONFIRMED", "REMEDIATION_PLANNED", "IN_PROGRESS",
  "FIX_CLAIMED", "VERIFICATION_PENDING", "REOPENED",
];

export function isV2Open(state: V2FindingLifecycle): boolean {
  return V2_OPEN_STATES.includes(state);
}
