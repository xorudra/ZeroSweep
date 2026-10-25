import type { ValidationConfidence, ValidationOutcome } from "./types";

/**
 * Finding updates from validation (Prompt 16 §36–§38). Validation moves
 * the finding's VALIDATION confidence — a dimension separate from
 * severity and from the scanner's confidence (§36). A successful SAFE
 * validation against the deterministic proof standard (the governed
 * recheck reproduced the exact original observation) may mark the
 * finding CONFIRMED; original scanner evidence is never overwritten
 * (§37). A failure to reproduce is NOT a false positive (§38).
 */

export interface FindingValidationUpdate {
  validationConfidence: ValidationConfidence;
  /** Prisma FindingVerificationStatus value to write — ONLY set when
   *  the deterministic proof standard is met (or an analyst attests). */
  verificationStatus?: "CONFIRMED";
  lastValidatedAt: string;
  /** Human-readable explanation recorded in finding history. */
  note: string;
}

export function confidenceUpdateForOutcome(
  outcome: ValidationOutcome,
  now: Date = new Date(),
): FindingValidationUpdate {
  const lastValidatedAt = now.toISOString();
  switch (outcome) {
    case "REPRODUCED":
      return {
        validationConfidence: "VERIFIED",
        verificationStatus: "CONFIRMED",
        lastValidatedAt,
        note: "safe validation reproduced the original observation — finding verified (§37)",
      };
    case "NOT_REPRODUCED":
      return {
        validationConfidence: "INCONCLUSIVE",
        lastValidatedAt,
        note: "safe validation did not reproduce the issue — this is NOT a false-positive determination (§38); use retesting to verify remediation",
      };
    case "FIXED":
      return {
        validationConfidence: "INCONCLUSIVE",
        lastValidatedAt,
        note: "validation observed the issue as corrected — lifecycle resolution still flows through retest/review, not validation (§38/§39)",
      };
    case "TARGET_CHANGED":
      return {
        validationConfidence: "INCONCLUSIVE",
        lastValidatedAt,
        note: "the target changed since detection — validation is inconclusive (§38)",
      };
    case "VALIDATION_BLOCKED":
      return {
        validationConfidence: "INCONCLUSIVE",
        lastValidatedAt,
        note: "validation was blocked by policy/scope/safety controls — no confidence change implied (§38)",
      };
    case "INCONCLUSIVE":
      return {
        validationConfidence: "INCONCLUSIVE",
        lastValidatedAt,
        note: "validation completed without a determinate result (§38)",
      };
  }
}

/** §32/§21: manual analyst validation is the ONLY path for classes the
 *  automated engine must not touch (e.g. RCE). An authorized analyst's
 *  attestation — with their own sanitized evidence — can verify a
 *  finding; ZeroSweep executes nothing for it. */
export function confidenceUpdateForManualValidation(
  outcome: "VERIFIED" | "NOT_REPRODUCED" | "INCONCLUSIVE",
  now: Date = new Date(),
): FindingValidationUpdate {
  const lastValidatedAt = now.toISOString();
  if (outcome === "VERIFIED") {
    return {
      validationConfidence: "VERIFIED",
      verificationStatus: "CONFIRMED",
      lastValidatedAt,
      note: "verified by an authorized analyst's manual validation record (§32) — no automated action was executed",
    };
  }
  if (outcome === "NOT_REPRODUCED") {
    return {
      validationConfidence: "INCONCLUSIVE",
      lastValidatedAt,
      note: "analyst could not reproduce the issue manually — not a false-positive determination (§38)",
    };
  }
  return {
    validationConfidence: "INCONCLUSIVE",
    lastValidatedAt,
    note: "manual validation was inconclusive (§32)",
  };
}
