import { computeRiskV2, type RiskV2Input, type RiskV2Result } from "../vulnmgmt/risk-v2";
import { riskBandForScore, type RiskBand } from "../vuln/analysis";

/**
 * Risk Engine V3 (Prompt 20 §20–§23). V3 PRESERVES the V2 calculation
 * (same base, same intel signals, same calc lineage) and layers the
 * additional §21 context signals on top: data sensitivity, exploitability
 * evidence, runtime signals, privilege context, attack-path context,
 * dependency reachability, affected-asset count, remediation
 * availability, environment and SLA state.
 *
 * §23 is a hard rule: every score ships with its contributing signals,
 * the signed adjustments, a confidence statement and an explicit list
 * of MISSING information. There are no magic scores.
 */

export const RISK_CALC_VERSION_V3 = "risk-v3.0";

export interface RiskV3Input extends RiskV2Input {
  /** §21: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED (asset-owner classified). */
  dataSensitivity?: string;
  /** §21: evidence a validation/runtime check confirmed exploitability signals (never the raw claim). */
  exploitabilityEvidence?: boolean;
  /** §21: runtime detection signal attached to this issue (e.g. Falco-class event correlation). */
  runtimeSignal?: boolean;
  /** §21: the affected identity/resource holds elevated privilege. */
  privilegeContext?: boolean;
  /** §21: the finding sits on a modelled attack path (defensive model, P15). */
  attackPathContext?: boolean;
  /** §21 (P12): dependency reachability — REACHABLE | UNREACHABLE | UNKNOWN. */
  dependencyReachability?: string;
  /** §21: how many assets share this root issue. */
  affectedAssetCount?: number;
  /** §21: a fix (patch/config change) is known to exist. */
  remediationAvailable?: boolean;
  /** §21: PRODUCTION | STAGING | DEVELOPMENT | LAB. */
  environment?: string;
  /** §21/§29: ON_TRACK | DUE_SOON | OVERDUE | PAUSED | NOT_APPLICABLE. */
  slaState?: string;
  /** Domain hint used only to decide which missing-info items apply. */
  sourceDomainHint?: string;
}

export interface RiskAdjustment {
  signal: string;
  delta: number;
  rationale: string;
}

export interface RiskV3Result extends Omit<RiskV2Result, "calcVersion"> {
  calcVersion: string;
  /** §23 explainability: signed adjustments from the V3 signal layer. */
  adjustments: RiskAdjustment[];
  /** §23: what the engine did NOT know — named, never hidden. */
  missingInformation: string[];
  /** §23: 0..1 confidence in the score given the available signals. */
  scoreConfidence: number;
  band: RiskBand;
}

const SENSITIVITY_DELTA: Record<string, number> = { RESTRICTED: 6, CONFIDENTIAL: 4, INTERNAL: 1, PUBLIC: 0 };
const ENV_DELTA: Record<string, number> = { PRODUCTION: 3, STAGING: 0, DEVELOPMENT: -3, LAB: -6 };

export function computeRiskV3(input: RiskV3Input): RiskV3Result {
  const v2 = computeRiskV2(input);
  const adjustments: RiskAdjustment[] = [];
  const missing: string[] = [];
  let score = v2.score;
  const apply = (signal: string, delta: number, rationale: string) => {
    if (delta === 0) return;
    score = Math.max(0, Math.min(100, score + delta));
    adjustments.push({ signal, delta, rationale });
  };

  if (v2.score === 0 && input.verificationStatus === "REJECTED") {
    return { ...v2, calcVersion: RISK_CALC_VERSION_V3, adjustments, missingInformation: missing, scoreConfidence: 1, band: v2.band };
  }

  // Data sensitivity (§21)
  if (input.dataSensitivity) {
    apply("dataSensitivity", SENSITIVITY_DELTA[input.dataSensitivity] ?? 0, `affected data classified ${input.dataSensitivity} (§21)`);
  } else missing.push("data sensitivity classification");

  // Environment (§21)
  if (input.environment) {
    apply("environment", ENV_DELTA[input.environment] ?? 0, `environment ${input.environment} (§21)`);
  } else missing.push("environment");

  // Exploitability evidence / runtime / privilege / attack-path context (§21)
  if (input.exploitabilityEvidence) apply("exploitabilityEvidence", 6, "deterministic validation or runtime evidence supports exploitability (§21)");
  if (input.runtimeSignal) apply("runtimeSignal", 5, "runtime detection signal correlated with this issue (§21)");
  if (input.privilegeContext) apply("privilegeContext", 4, "affected resource/identity holds elevated privilege (§21)");
  if (input.attackPathContext) apply("attackPathContext", 4, "finding participates in a modelled attack path (§21)");

  // Dependency reachability (§21): unreachable code is real but less urgent.
  if (input.dependencyReachability === "REACHABLE") apply("dependencyReachability", 3, "vulnerable dependency is reachable (§21)");
  else if (input.dependencyReachability === "UNREACHABLE") apply("dependencyReachability", -6, "vulnerable dependency is not reachable — score reduced, finding retained (§21)");
  else if (input.sourceDomainHint === "SCA") missing.push("dependency reachability");

  // Affected-asset breadth (§21)
  if (input.affectedAssetCount !== undefined) {
    if (input.affectedAssetCount >= 10) apply("affectedAssets", 4, `${input.affectedAssetCount} assets share this root issue (§21)`);
    else if (input.affectedAssetCount >= 3) apply("affectedAssets", 2, `${input.affectedAssetCount} assets share this root issue (§21)`);
  }

  // Remediation availability (§21): a known fix slightly raises urgency
  // (cheap to close), its absence never hides the issue.
  if (input.remediationAvailable === false) missing.push("remediation availability");

  // SLA state (§21): overdue work escalates mildly — the deadline system
  // itself carries the primary pressure.
  if (input.slaState === "OVERDUE") apply("slaState", 3, "remediation SLA is OVERDUE (§21)");
  if (!input.slaState) missing.push("SLA state");

  if (input.assetCriticality === undefined) missing.push("asset criticality");
  if (input.cvssScore === undefined) missing.push("CVSS score");

  score = Math.max(0, Math.min(100, Math.round(score)));
  // Confidence in the SCORE (§23): starts at the finding confidence and
  // decays with each missing signal family — reported, never hidden.
  const scoreConfidence = Math.max(0.1, Math.min(1, input.confidence * (1 - 0.06 * missing.length)));

  return {
    ...v2,
    score,
    band: riskBandForScore(score),
    calcVersion: RISK_CALC_VERSION_V3,
    factors: [...v2.factors, ...adjustments.map((a) => `${a.delta >= 0 ? "+" : ""}${a.delta} ${a.signal}: ${a.rationale}`)],
    adjustments,
    missingInformation: missing,
    scoreConfidence: Math.round(scoreConfidence * 100) / 100,
  };
}
