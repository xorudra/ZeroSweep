import type { Severity } from "@zerosweep/types";

/**
 * Scanner severity/confidence normalization (Prompt 8 §34–§35).
 *
 * Each product speaks its own dialect. These tables are EXPLICIT and
 * per-product on purpose: "Burp High", "ZAP High" and "Nuclei High" are
 * NOT assumed equivalent — each is first mapped to the ZeroSweep severity
 * scale by its own table, and the final risk is computed afterwards by
 * the ZeroSweep RiskEngine from the normalized record (never by copying a
 * vendor's implied risk across).
 *
 * Confidence (§35): scanner confidence is preserved as the finding's
 * source confidence (0..1). NO mapping here can produce a CONFIRMED
 * verification status — confirmation requires deterministic verification
 * or human review in the correlation/review pipeline, however certain a
 * scanner claims to be.
 */

export type ScannerConfidenceBand = "LOW" | "MEDIUM" | "HIGH";

export interface MappedConfidence {
  /** Source confidence 0..1 used by correlation. */
  score: number;
  band: ScannerConfidenceBand;
  /** The scanner's own label, preserved for the evidence record. */
  label: string;
}

// ------------------------------- ZAP (§34) -------------------------------
// ZAP riskcode: 0 Informational, 1 Low, 2 Medium, 3 High (no Critical).
export const ZAP_RISK_TO_SEVERITY: Record<string, Severity> = {
  "0": "INFORMATIONAL", informational: "INFORMATIONAL", info: "INFORMATIONAL",
  "1": "LOW", low: "LOW",
  "2": "MEDIUM", medium: "MEDIUM",
  "3": "HIGH", high: "HIGH",
};
// ZAP confidence: 0 Other, 1 Low, 2 Medium, 3 High, 4 Confirmed.
export const ZAP_CONFIDENCE: Record<string, MappedConfidence> = {
  "0": { score: 0.3, band: "LOW", label: "Other" },
  "1": { score: 0.4, band: "LOW", label: "Low" },
  "2": { score: 0.6, band: "MEDIUM", label: "Medium" },
  "3": { score: 0.8, band: "HIGH", label: "High" },
  // §35: even ZAP "Confirmed" is a scanner CLAIM. It maps to the highest
  // source confidence but the finding's verification status still starts
  // UNVERIFIED — correlation/review decides confirmation.
  "4": { score: 0.9, band: "HIGH", label: "Confirmed (scanner-reported)" },
  low: { score: 0.4, band: "LOW", label: "Low" },
  medium: { score: 0.6, band: "MEDIUM", label: "Medium" },
  high: { score: 0.8, band: "HIGH", label: "High" },
  confirmed: { score: 0.9, band: "HIGH", label: "Confirmed (scanner-reported)" },
};

export function mapZapSeverity(riskcode: unknown, riskdesc?: unknown): Severity {
  const key = String(riskcode ?? "").trim().toLowerCase();
  if (ZAP_RISK_TO_SEVERITY[key]) return ZAP_RISK_TO_SEVERITY[key];
  const desc = typeof riskdesc === "string" ? riskdesc.trim().toLowerCase().split(/\s+/)[0] ?? "" : "";
  return ZAP_RISK_TO_SEVERITY[desc] ?? "INFORMATIONAL";
}

export function mapZapConfidence(confidence: unknown): MappedConfidence {
  const key = String(confidence ?? "").trim().toLowerCase();
  return ZAP_CONFIDENCE[key] ?? { score: 0.5, band: "MEDIUM", label: "Unspecified" };
}

// ------------------------------- Burp (§34) ------------------------------
// Burp severity: High / Medium / Low / Information. Burp has no Critical.
export const BURP_SEVERITY: Record<string, Severity> = {
  high: "HIGH", medium: "MEDIUM", low: "LOW",
  information: "INFORMATIONAL", informational: "INFORMATIONAL",
};
// Burp confidence: Certain / Firm / Tentative.
export const BURP_CONFIDENCE: Record<string, MappedConfidence> = {
  certain: { score: 0.9, band: "HIGH", label: "Certain" },
  firm: { score: 0.7, band: "MEDIUM", label: "Firm" },
  tentative: { score: 0.45, band: "LOW", label: "Tentative" },
};

export function mapBurpSeverity(raw: unknown): Severity {
  return BURP_SEVERITY[String(raw ?? "").trim().toLowerCase()] ?? "INFORMATIONAL";
}
export function mapBurpConfidence(raw: unknown): MappedConfidence {
  return BURP_CONFIDENCE[String(raw ?? "").trim().toLowerCase()] ?? { score: 0.5, band: "MEDIUM", label: "Unspecified" };
}

// ------------------------------- Caido (§34) ------------------------------
// Caido findings carry a severity label in exports; treated as its own
// dialect with the same conservative posture.
export const CAIDO_SEVERITY: Record<string, Severity> = {
  critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", moderate: "MEDIUM",
  low: "LOW", info: "INFORMATIONAL", informational: "INFORMATIONAL", none: "INFORMATIONAL",
};
export function mapCaidoSeverity(raw: unknown): Severity {
  return CAIDO_SEVERITY[String(raw ?? "").trim().toLowerCase()] ?? "INFORMATIONAL";
}
