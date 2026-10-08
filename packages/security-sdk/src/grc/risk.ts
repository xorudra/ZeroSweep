import type { ControlEffectiveness, ImpactDimension } from "./types";
import { IMPACT_DIMENSIONS } from "./types";

/**
 * Risk register mathematics (Prompt 26 §45–§49). Deterministic and
 * organization-configurable within platform bounds (§47): likelihood
 * and per-dimension impact are integers 1–5; the matrix maps the
 * inherent score (likelihood × max impact) to a band. Residual risk
 * (§49) is computed ONLY when control effectiveness is known — with
 * insufficient evidence the residual is null and the caller must show
 * "not assessed", never an invented exact number.
 */

export interface RiskMatrixConfig {
  /** Band upper bounds over the 1..25 score: [low, medium, high]. */
  bands: { lowMax: number; mediumMax: number; highMax: number };
  /** Effectiveness → residual multiplier applied to the inherent score. */
  effectivenessMultipliers: Record<Exclude<ControlEffectiveness, "NOT_TESTED" | "INCONCLUSIVE">, number>;
}

export const DEFAULT_RISK_MATRIX: RiskMatrixConfig = {
  bands: { lowMax: 4, mediumMax: 9, highMax: 16 },
  effectivenessMultipliers: { EFFECTIVE: 0.4, PARTIALLY_EFFECTIVE: 0.7, INEFFECTIVE: 1 },
};

export type GrcRiskBand = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export function validateMatrixConfig(cfg: RiskMatrixConfig): string[] {
  const errors: string[] = [];
  const { lowMax, mediumMax, highMax } = cfg.bands;
  if (!(lowMax >= 1 && lowMax < mediumMax && mediumMax < highMax && highMax < 25)) {
    errors.push("risk matrix bands must satisfy 1 <= lowMax < mediumMax < highMax < 25 (platform bounds, §47)");
  }
  for (const [k, v] of Object.entries(cfg.effectivenessMultipliers)) {
    if (!(v > 0 && v <= 1)) errors.push(`effectiveness multiplier for ${k} must be within (0, 1]`);
  }
  return errors;
}

export function clampScore(value: number, label: string): number {
  if (!Number.isInteger(value) || value < 1 || value > 5) {
    throw new Error(`${label} must be an integer between 1 and 5 (§45/§46)`);
  }
  return value;
}

export interface InherentRiskInput {
  likelihood: number;
  impacts: Partial<Record<ImpactDimension, number>>;
}

export interface RiskComputation {
  inherentScore: number;
  inherentBand: GrcRiskBand;
  maxImpact: number;
  residualScore: number | null;
  residualBand: GrcRiskBand | null;
  residualBasis: string;
}

export function bandForScore(score: number, cfg: RiskMatrixConfig = DEFAULT_RISK_MATRIX): GrcRiskBand {
  if (score <= cfg.bands.lowMax) return "LOW";
  if (score <= cfg.bands.mediumMax) return "MEDIUM";
  if (score <= cfg.bands.highMax) return "HIGH";
  return "CRITICAL";
}

export function computeRegisterRisk(
  input: InherentRiskInput,
  effectiveness: ControlEffectiveness | null,
  cfg: RiskMatrixConfig = DEFAULT_RISK_MATRIX,
): RiskComputation {
  const likelihood = clampScore(input.likelihood, "likelihood");
  const dims = Object.entries(input.impacts).filter(([, v]) => v !== undefined);
  if (dims.length === 0) throw new Error("at least one impact dimension is required (§46)");
  for (const [dim, v] of dims) {
    if (!IMPACT_DIMENSIONS.includes(dim as ImpactDimension)) throw new Error(`unknown impact dimension ${dim}`);
    clampScore(v as number, `impact.${dim}`);
  }
  const maxImpact = Math.max(...dims.map(([, v]) => v as number));
  const inherentScore = likelihood * maxImpact;
  const inherentBand = bandForScore(inherentScore, cfg);

  let residualScore: number | null = null;
  let residualBand: GrcRiskBand | null = null;
  let residualBasis = "Residual risk not assessed: control effectiveness is unknown (§49).";
  if (effectiveness && effectiveness !== "NOT_TESTED" && effectiveness !== "INCONCLUSIVE") {
    const multiplier = cfg.effectivenessMultipliers[effectiveness];
    residualScore = Math.max(1, Math.round(inherentScore * multiplier));
    residualBand = bandForScore(residualScore, cfg);
    residualBasis = `Residual = inherent ${inherentScore} × ${multiplier} (control effectiveness ${effectiveness}) = ${residualScore}.`;
  }
  return { inherentScore, inherentBand, maxImpact, residualScore, residualBand, residualBasis };
}

/** §57/§130: high-risk acceptance requires a distinct approver under SoD. */
export function evaluateAcceptanceSod(input: {
  requesterId: string;
  approverId: string;
  inherentBand: GrcRiskBand;
  sodRequiredForBands: GrcRiskBand[];
}): { allowed: boolean; reason: string } {
  if (input.requesterId === input.approverId && input.sodRequiredForBands.includes(input.inherentBand)) {
    return { allowed: false, reason: `Segregation of duties: the requester cannot approve their own ${input.inherentBand} risk acceptance (§57).` };
  }
  return { allowed: true, reason: "Approver is independent of the requester." };
}

/** §59/§131: an expired acceptance never silently remains accepted. */
export function acceptanceState(input: { status: string; expiresAt: string | null }, now: Date): string {
  if (input.status === "ACCEPTED" && input.expiresAt && new Date(input.expiresAt).getTime() <= now.getTime()) {
    return "REVIEW_REQUIRED";
  }
  return input.status;
}
