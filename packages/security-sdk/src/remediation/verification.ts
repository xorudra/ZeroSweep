import type { VerificationMethod, VerificationOutcome } from "./types";

/**
 * Verification policy + outcome evaluation (Prompt 31 §52–§67).
 * The non-negotiables live here as pure logic:
 * - a scanner ERROR is never a pass (§63);
 * - insufficient evidence is INCONCLUSIVE and closes nothing (§62);
 * - ONE absent observation does not prove a fix for finding types whose
 *   policy demands consecutive clean observations (§64/§65);
 * - a still-present observation is FAILED and returns the case to
 *   actionable work (§139).
 */
export interface VerificationPolicyEntry {
  methods: VerificationMethod[];
  /** Consecutive clean observations required before VERIFIED_FIXED. */
  requiredCleanObservations: number;
  /** Finding sources/categories this entry applies to (lowercase keys). */
  appliesTo: string[];
}

export const VERIFICATION_POLICY: VerificationPolicyEntry[] = [
  { appliesTo: ["sast", "source", "code"], methods: ["SAST_RESCAN", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
  { appliesTo: ["sca", "dependency", "sbom"], methods: ["SCA_RESCAN", "SBOM_REEVALUATION", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
  { appliesTo: ["web", "dast", "api"], methods: ["SAFE_RESCAN", "TARGETED_RETEST", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
  { appliesTo: ["network", "service"], methods: ["TARGETED_RETEST", "CONFIGURATION_RECHECK", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
  { appliesTo: ["cloud", "posture"], methods: ["CLOUD_POSTURE_RECHECK", "CONFIGURATION_RECHECK", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
  { appliesTo: ["container", "image", "kubernetes", "k8s"], methods: ["SBOM_REEVALUATION", "CONFIGURATION_RECHECK", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
  { appliesTo: ["mobile", "binary"], methods: ["SAST_RESCAN", "SBOM_REEVALUATION", "MANUAL_EVIDENCE_REVIEW"], requiredCleanObservations: 1 },
];

const DEFAULT_ENTRY: VerificationPolicyEntry = {
  appliesTo: ["*"],
  methods: ["TARGETED_RETEST", "SAFE_RESCAN", "MANUAL_EVIDENCE_REVIEW"],
  requiredCleanObservations: 1,
};

/** Method allowance for a finding (§54). Category comes from the
 *  finding's class/source/tooling; unknown categories fall back to the
 *  conservative default (targeted retest / safe rescan / manual review). */
export function verificationPolicyFor(category: string | null | undefined): VerificationPolicyEntry {
  const key = (category ?? "").toLowerCase();
  if (!key) return DEFAULT_ENTRY;
  for (const entry of VERIFICATION_POLICY) {
    if (entry.appliesTo.some((a) => key.includes(a))) return entry;
  }
  return DEFAULT_ENTRY;
}

export function isVerificationMethodAllowed(category: string | null | undefined, method: VerificationMethod): boolean {
  return verificationPolicyFor(category).methods.includes(method);
}

export interface VerificationObservation {
  /** What the scanner/tool reported. ERROR dominates everything (§63). */
  scannerStatus: "OK" | "ERROR";
  /** Whether the vulnerability was still observed after the fix. */
  stillPresent: boolean | null;
  /** Whether the evidence suffices for a determination at all (§62). */
  evidenceSufficient: boolean;
}

export interface VerificationEvaluation {
  outcome: VerificationOutcome;
  /** Clean observations accumulated AFTER this one. */
  cleanObservations: number;
  /** The case-level effect the caller must apply. */
  caseEffect: "VERIFIED_FIXED" | "RETURN_TO_ACTIONABLE" | "STAY_PENDING" | "NONE";
  reason: string;
}

export function evaluateVerification(input: {
  observation: VerificationObservation;
  previousCleanObservations: number;
  requiredCleanObservations: number;
}): VerificationEvaluation {
  const { observation } = input;
  const required = Math.max(1, input.requiredCleanObservations);
  if (observation.scannerStatus === "ERROR") {
    return {
      outcome: "ERROR", cleanObservations: input.previousCleanObservations, caseEffect: "NONE",
      reason: "scanner error — an error is never a pass (§63)",
    };
  }
  if (!observation.evidenceSufficient || observation.stillPresent === null) {
    return {
      outcome: "INCONCLUSIVE", cleanObservations: input.previousCleanObservations, caseEffect: "STAY_PENDING",
      reason: "evidence insufficient for a determination — the finding is not closed (§62)",
    };
  }
  if (observation.stillPresent) {
    return {
      outcome: "FAILED", cleanObservations: 0, caseEffect: "RETURN_TO_ACTIONABLE",
      reason: "vulnerability still present after the claimed fix (§139)",
    };
  }
  const clean = input.previousCleanObservations + 1;
  if (clean < required) {
    return {
      outcome: "PENDING_CONFIRMATION", cleanObservations: clean, caseEffect: "STAY_PENDING",
      reason: `clean observation ${clean}/${required} — confirmation policy requires ${required} consecutive clean observations (§65)`,
    };
  }
  return {
    outcome: "PASSED", cleanObservations: clean, caseEffect: "VERIFIED_FIXED",
    reason: `verification satisfied: ${clean} consecutive clean observation(s) (§61)`,
  };
}

/** High-risk determination for SoD / dual-approval policy (§67/§122). */
export function isHighRiskRemediation(input: {
  priority?: string | null;
  severity: string;
  kevListed: boolean;
}): boolean {
  return input.priority === "P0" || input.priority === "P1" || input.severity === "CRITICAL" || input.kevListed;
}
