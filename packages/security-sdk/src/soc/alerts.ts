import { createHash } from "node:crypto";
import type { AlertPriority, DetectionConfidence, SocSeverity } from "./types";

/**
 * Alert fingerprinting + prioritization (Prompt 28 §32–§35).
 * Repeated equivalent detections update ONE alert lifecycle instead
 * of generating alert storms (§32/§136). Priority is a deterministic
 * function of stated inputs (§34) — the same inputs always produce
 * the same priority, and every factor is recorded for explainability.
 */

/** Named socAlertFingerprint to avoid colliding with the P22
 *  notification alertFingerprint export. */
export function socAlertFingerprint(input: {
  ruleId: string;
  ruleVersion: number;
  groupKey?: string;
  assetId?: string;
  identityReference?: string;
  indicatorId?: string;
}): string {
  const basis = [input.ruleId, `v${input.ruleVersion}`, input.groupKey ?? "", input.assetId ?? "", input.identityReference ?? "", input.indicatorId ?? ""].join("|");
  return createHash("sha256").update(basis).digest("hex").slice(0, 40);
}

const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 40, HIGH: 30, MEDIUM: 18, LOW: 8, INFO: 2 };
const CONFIDENCE_WEIGHT: Record<DetectionConfidence, number> = { HIGH: 15, MEDIUM: 8, LOW: 3 };

export interface PriorityInputs {
  severity: SocSeverity | string;
  confidence: DetectionConfidence;
  assetCriticality?: string; // CRITICAL | HIGH | MEDIUM | LOW
  internetExposed?: boolean;
  identityPrivileged?: boolean;
  kev?: boolean;
  threatIntelConfidence?: number; // 0..100
  correlationSignalCount?: number;
}

export interface PriorityResult {
  priority: AlertPriority;
  score: number;
  factors: Record<string, number>;
}

export function computeAlertPriority(input: PriorityInputs): PriorityResult {
  const factors: Record<string, number> = {
    severity: SEVERITY_WEIGHT[input.severity] ?? 2,
    confidence: CONFIDENCE_WEIGHT[input.confidence] ?? 3,
    assetCriticality: input.assetCriticality === "CRITICAL" ? 15 : input.assetCriticality === "HIGH" ? 10 : input.assetCriticality === "MEDIUM" ? 5 : 0,
    internetExposure: input.internetExposed ? 10 : 0,
    identityPrivilege: input.identityPrivileged ? 10 : 0,
    kev: input.kev ? 15 : 0,
    threatIntel: input.threatIntelConfidence !== undefined ? Math.round(input.threatIntelConfidence / 10) : 0,
    correlation: Math.min(10, (input.correlationSignalCount ?? 0) * 3),
  };
  const score = Object.values(factors).reduce((a, b) => a + b, 0);
  const priority: AlertPriority = score >= 75 ? "P1" : score >= 50 ? "P2" : score >= 28 ? "P3" : "P4";
  return { priority, score, factors };
}

/** §123 metric definitions (documented, never mixed):
 *  - MTTA (mean time to acknowledge): alert created → first triage.
 *  - MTTC (mean time to contain): incident declared → contained.
 *  - MTTR-IR (incident response): incident declared → recovered/closed.
 *  These are computed from recorded timestamps only; missing
 *  timestamps exclude the record instead of inventing durations. */
export function meanSeconds(durationsSeconds: number[]): number | null {
  if (durationsSeconds.length === 0) return null;
  return Math.round(durationsSeconds.reduce((a, b) => a + b, 0) / durationsSeconds.length);
}
