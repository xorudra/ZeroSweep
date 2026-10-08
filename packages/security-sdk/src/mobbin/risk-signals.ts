/**
 * Prompt 35 §111/§112 — contextual risk signals for Risk Engine V3.
 *
 * Mobile/binary risk is contextual: production status, application
 * criticality, internet/API exposure, secret exposure, runtime
 * confirmation, CVE/KEV state and data-sensitivity metadata. A
 * static observation by itself is weak evidence — §112: a
 * decompilation observation alone NEVER becomes critical risk, and
 * §66: function/import presence alone is not proof of
 * exploitability. Signals are emitted with their weights so the
 * Risk Engine's explanation stays deterministic and auditable.
 */
export interface MobbinRiskSignalInput {
  environment: string; // PRODUCTION | STAGING | DEVELOPMENT | LAB | UNKNOWN
  criticality: string; // LOW | MEDIUM | HIGH | CRITICAL
  internetExposed: boolean;
  secretExposure: boolean;
  runtimeConfirmed: boolean;
  kevListed: boolean;
  epss: number | null; // null stays null — never invented (§P30 discipline)
  dataSensitivity: string; // NONE | LOW | MEDIUM | HIGH
  evidenceKind: "STATIC_OBSERVATION" | "DECOMPILATION_OBSERVATION" | "RUNTIME_OBSERVATION" | "SCANNER_CONFIRMED";
  baseSeverity: string; // INFORMATIONAL | LOW | MEDIUM | HIGH | CRITICAL
}

export interface MobbinRiskSignals {
  signals: { name: string; value: string | number | boolean | null; weight: number }[];
  /** §112 guard: the severity ceiling this evidence may support. */
  severityCeiling: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  explanation: string[];
}

const SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export function mobileBinaryRiskSignals(input: MobbinRiskSignalInput): MobbinRiskSignals {
  const explanation: string[] = [];
  const signals: MobbinRiskSignals["signals"] = [
    { name: "environment", value: input.environment, weight: input.environment === "PRODUCTION" ? 15 : 0 },
    { name: "criticality", value: input.criticality, weight: input.criticality === "CRITICAL" ? 15 : input.criticality === "HIGH" ? 10 : 0 },
    { name: "internetExposed", value: input.internetExposed, weight: input.internetExposed ? 10 : 0 },
    { name: "secretExposure", value: input.secretExposure, weight: input.secretExposure ? 15 : 0 },
    { name: "runtimeConfirmed", value: input.runtimeConfirmed, weight: input.runtimeConfirmed ? 15 : 0 },
    { name: "kevListed", value: input.kevListed, weight: input.kevListed ? 15 : 0 },
    { name: "epss", value: input.epss, weight: input.epss === null ? 0 : Math.round(input.epss * 10) },
    { name: "dataSensitivity", value: input.dataSensitivity, weight: input.dataSensitivity === "HIGH" ? 5 : 0 },
  ];
  // §112: decompilation-only or static-only evidence caps the
  // supported severity — confirmation requires runtime evidence or
  // scanner confirmation, not a second look at the same observation.
  let ceiling: MobbinRiskSignals["severityCeiling"] = "CRITICAL";
  if (input.evidenceKind === "DECOMPILATION_OBSERVATION") {
    ceiling = "MEDIUM";
    explanation.push("decompilation observation alone caps severity at MEDIUM (§112)");
  } else if (input.evidenceKind === "STATIC_OBSERVATION") {
    ceiling = "HIGH";
    explanation.push("static observation alone caps severity at HIGH (§66/§112)");
  }
  if (input.runtimeConfirmed) explanation.push("runtime confirmation present — full severity range supported (§111)");
  if (input.epss === null) explanation.push("EPSS absent — recorded as null, never 0");
  const baseIdx = SEVERITY_ORDER.indexOf(input.baseSeverity as typeof SEVERITY_ORDER[number]);
  const ceilIdx = SEVERITY_ORDER.indexOf(ceiling);
  if (baseIdx > ceilIdx) explanation.push(`base severity ${input.baseSeverity} exceeds the evidence ceiling ${ceiling} — Risk Engine must clamp`);
  return { signals, severityCeiling: ceiling, explanation };
}
