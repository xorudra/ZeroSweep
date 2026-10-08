import type {
  ControlConfidence, ControlResult, ControlSignalData, EvidenceStatus, RequirementResult,
} from "./types";

/**
 * Control evaluation + evidence freshness + requirement roll-up
 * (Prompt 26 §24–§37). Pure functions over snapshots so historical
 * assessments never change when live state changes (§21/§125).
 */

export interface EvaluationOutcome {
  result: ControlResult;
  confidence: ControlConfidence;
  reason: string;
  effectiveness: "NOT_TESTED" | "EFFECTIVE" | "PARTIALLY_EFFECTIVE" | "INEFFECTIVE" | "INCONCLUSIVE";
}

/**
 * Evaluate a control from its required signals (§29–§32). No signal
 * data → INCONCLUSIVE with LOW confidence: absence of evidence is
 * never a pass. Confidence reflects evidence completeness.
 */
export function evaluateControl(signals: ControlSignalData[], requiredSignalKeys: string[]): EvaluationOutcome {
  if (requiredSignalKeys.length === 0) {
    return {
      result: "INCONCLUSIVE", confidence: "LOW", effectiveness: "INCONCLUSIVE",
      reason: "Control has no automated signals; it requires manual evidence and human review (§38).",
    };
  }
  const byKey = new Map(signals.map((s) => [s.key, s]));
  const known = requiredSignalKeys.filter((k) => byKey.get(k)?.state != null);
  if (known.length === 0) {
    return {
      result: "INCONCLUSIVE", confidence: "LOW", effectiveness: "NOT_TESTED",
      reason: "No signal data available for this control; it has not been tested.",
    };
  }
  const completeness = known.length / requiredSignalKeys.length;
  const confidence: ControlConfidence = completeness >= 1 ? "HIGH" : completeness >= 0.5 ? "MEDIUM" : "LOW";
  const states = known.map((k) => byKey.get(k)!.state);
  const failed = states.filter((s) => s === "FAIL").length;
  const partial = states.filter((s) => s === "PARTIAL").length;
  if (failed > 0 && partial === 0 && failed === states.length) {
    return { result: "FAIL", confidence, effectiveness: "INEFFECTIVE", reason: `All observed signals failing (${failed}/${requiredSignalKeys.length} required signals observed).` };
  }
  if (failed > 0 || partial > 0) {
    return { result: "PARTIAL", confidence, effectiveness: "PARTIALLY_EFFECTIVE", reason: `Signals degraded: ${failed} failing, ${partial} partial of ${states.length} observed.` };
  }
  if (completeness < 1) {
    return { result: "PARTIAL", confidence, effectiveness: "PARTIALLY_EFFECTIVE", reason: `All observed signals pass but only ${known.length}/${requiredSignalKeys.length} required signals have data.` };
  }
  return { result: "PASS", confidence, effectiveness: "EFFECTIVE", reason: "All required signals pass with current evidence." };
}

/** §25/§126: freshness is a pure function of collection time + policy. */
export function evidenceFreshness(
  collectedAt: string,
  policy: { staleAfterDays: number; expireAfterDays: number },
  now: Date,
  storedStatus?: EvidenceStatus,
): EvidenceStatus {
  if (storedStatus === "INVALID" || storedStatus === "SUPERSEDED") return storedStatus;
  const ageDays = (now.getTime() - new Date(collectedAt).getTime()) / 86_400_000;
  if (ageDays >= policy.expireAfterDays) return "EXPIRED";
  if (ageDays >= policy.staleAfterDays) return "STALE";
  return "CURRENT";
}

export interface MappedControlOutcome {
  mappingType: "DIRECT" | "PARTIAL" | "SUPPORTING";
  coverage: number; // 0..1
  controlResult: ControlResult;
  hasCurrentEvidence: boolean;
  manuallySatisfied: boolean; // human-reviewed manual evidence accepted (§38)
}

/**
 * Requirement result from mapped controls (§36/§37 + §11/§124). A
 * requirement is COMPLIANT only when DIRECT/PARTIAL mappings with
 * combined coverage >= 1 all pass on current evidence (or an accepted
 * manual review covers the remainder). Partial technical support of
 * an administrative requirement can never yield COMPLIANT on its own.
 */
export function requirementResult(outcomes: MappedControlOutcome[]): RequirementResult {
  if (outcomes.length === 0) return "NOT_ASSESSED";
  const substantive = outcomes.filter((o) => o.mappingType !== "SUPPORTING");
  if (substantive.length === 0) {
    // Supporting mappings alone can never establish compliance (§11).
    return outcomes.some((o) => o.manuallySatisfied) ? "PARTIALLY_COMPLIANT" : "NOT_ASSESSED";
  }
  if (substantive.some((o) => o.controlResult === "FAIL")) return "NON_COMPLIANT";
  const coverage = Math.min(1, substantive.reduce((sum, o) => sum + o.coverage, 0));
  const manualRemainder = outcomes.some((o) => o.manuallySatisfied);
  const allPassCurrent = substantive.every((o) => o.controlResult === "PASS" && o.hasCurrentEvidence);
  if (allPassCurrent && (coverage >= 1 || manualRemainder)) return "COMPLIANT";
  if (substantive.some((o) => o.controlResult === "PASS" || o.controlResult === "PARTIAL") || manualRemainder) {
    return "PARTIALLY_COMPLIANT";
  }
  return "NOT_ASSESSED";
}

/** §82/§83: coverage metrics — labelled Assessment Coverage / Control
 *  Status, never a certification score. */
export interface CoverageMetrics {
  requirementsTotal: number;
  requirementsAssessed: number;
  controlsTotal: number;
  controlsImplemented: number;
  controlsTested: number;
  automatedControls: number;
  evidenceCurrent: number;
  evidenceTotal: number;
  manualEvidencePending: number;
  /** requirementsAssessed / requirementsTotal, 0 when no requirements. */
  assessmentCoverage: number;
}

export function coverageMetrics(input: Omit<CoverageMetrics, "assessmentCoverage">): CoverageMetrics {
  return {
    ...input,
    assessmentCoverage: input.requirementsTotal === 0 ? 0 : input.requirementsAssessed / input.requirementsTotal,
  };
}
