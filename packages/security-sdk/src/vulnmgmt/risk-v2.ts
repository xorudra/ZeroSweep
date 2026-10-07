import type { Severity } from "@dsrclone/types";
import { computeRisk, riskBandForScore, type RiskBand } from "../vuln/analysis";
import type { FindingEnrichment } from "./enrichment";

/**
 * Risk Engine V2 (Prompt 11 §37–§40). Builds on the Phase 7 deterministic
 * engine — the technical score still comes from computeRisk — and adds
 * the intelligence/context signals this phase introduces: EPSS, CISA KEV,
 * public-exploit-reference presence and finding age. Every output is
 * explained factor-by-factor (§38) and records the calculation version +
 * intelligence snapshot used (§31).
 *
 * Severity and remediation PRIORITY are separate (§39): severity is what
 * the scanner measured; priority is what the organization should fix
 * first. KEV listing escalates priority by a full band; a public exploit
 * reference is one contextual signal (§21) and NEVER marks a finding
 * confirmed-exploitable.
 */

export const RISK_CALC_VERSION_V2 = "risk-v2.1";

export type RemediationPriority = "P0" | "P1" | "P2" | "P3" | "P4";

export interface RiskV2Input {
  severity: Severity;
  /** Effective CVSS (after §32 trust resolution) when available. */
  cvssScore?: number;
  confidence: number;
  assetCriticality?: string;
  internetExposed?: boolean;
  verificationStatus?: string;
  enrichment?: FindingEnrichment;
  /** Whole days since first seen — older unremediated findings escalate mildly. */
  ageDays?: number;
}

export interface RiskV2Result {
  score: number;
  band: RiskBand;
  priority: RemediationPriority;
  factors: string[];
  /** V1 explanation lines preserved for continuity. */
  baseExplanation: string[];
  calcVersion: string;
  intelSnapshot?: string;
}

const PRIORITY_ORDER: RemediationPriority[] = ["P0", "P1", "P2", "P3", "P4"];

export function escalatePriority(priority: RemediationPriority, steps: number): RemediationPriority {
  const idx = Math.max(0, PRIORITY_ORDER.indexOf(priority) - steps);
  return PRIORITY_ORDER[idx]!;
}

/** Documented base mapping (§40): score band → priority before context. */
export function basePriorityForScore(score: number): RemediationPriority {
  if (score >= 90) return "P0";
  if (score >= 70) return "P1";
  if (score >= 40) return "P2";
  if (score >= 10) return "P3";
  return "P4";
}

export function computeRiskV2(input: RiskV2Input & { exploitReferenceExists?: boolean }): RiskV2Result {
  const base = computeRisk({
    severity: input.severity,
    cvssScore: input.cvssScore,
    confidence: input.confidence,
    assetCriticality: input.assetCriticality,
    internetExposed: input.internetExposed,
    verificationStatus: input.verificationStatus,
  });
  const factors: string[] = [];
  let score = base.score;
  const enr = input.enrichment;

  if (input.verificationStatus === "REJECTED") {
    return {
      score: 0, band: "INFORMATIONAL", priority: "P4",
      factors: ["finding REJECTED in review — priority P4, risk 0"],
      baseExplanation: base.explanation, calcVersion: RISK_CALC_VERSION_V2,
      ...(enr ? { intelSnapshot: enr.snapshotId } : {}),
    };
  }

  const kevListed = enr?.kevListed ?? false;
  if (kevListed) {
    score = Math.min(100, score + 10);
    factors.push("+10 CISA KEV-listed vulnerability (known exploited) (§28)");
  }
  const epss = enr?.epss;
  if (epss) {
    if (epss.score >= 0.5) { score = Math.min(100, score + 6); factors.push(`+6 EPSS ${epss.score} ≥ 0.5 — high exploitation probability (§27)`); }
    else if (epss.score >= 0.1) { score = Math.min(100, score + 3); factors.push(`+3 EPSS ${epss.score} ≥ 0.1 (§27)`); }
    else factors.push(`EPSS ${epss.score} below 0.1 — no score adjustment (§27)`);
  }
  const exploitRef = input.exploitReferenceExists ?? false;
  if (exploitRef) {
    score = Math.min(100, score + 4);
    factors.push("+4 public exploit reference exists — contextual signal only, NOT confirmed exploitable (§21)");
  }
  if (input.ageDays !== undefined && input.ageDays >= 90 && score > 0) {
    score = Math.min(100, score + 2);
    factors.push(`+2 finding age ${input.ageDays}d ≥ 90d unremediated`);
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const band = riskBandForScore(score);
  let priority = basePriorityForScore(score);
  factors.push(`priority ${priority} from score ${score} (band ${band})`);
  // §39: KEV escalates PRIORITY a full band beyond what the score alone
  // gives — severity/score are unchanged, fix order is what moves.
  if (kevListed) {
    const escalated = escalatePriority(priority, 1);
    if (escalated !== priority) factors.push(`priority escalated ${priority} → ${escalated}: KEV-listed (§39)`);
    priority = escalated;
  }
  if (exploitRef && epss && epss.score >= 0.5) {
    const escalated = escalatePriority(priority, 1);
    if (escalated !== priority) factors.push(`priority escalated ${priority} → ${escalated}: public exploit reference + EPSS ≥ 0.5`);
    priority = escalated;
  }

  return {
    score, band, priority, factors,
    baseExplanation: base.explanation,
    calcVersion: RISK_CALC_VERSION_V2,
    ...(enr ? { intelSnapshot: enr.snapshotId } : {}),
  };
}
