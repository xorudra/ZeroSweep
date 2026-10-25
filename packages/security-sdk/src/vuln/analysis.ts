import { createHash } from "node:crypto";
import type { Severity } from "@zerosweep/types";

/**
 * Fingerprinting, confidence and risk (Prompt 7 §19/§22/§23/§34/§35).
 * Everything here is deterministic and explained in the output — no AI,
 * no opaque scoring, no external threat intelligence (§34).
 */

export interface FingerprintInput {
  host: string;
  port?: number;
  endpoint?: string;
  parameter?: string;
  vulnClass: string;
  cve?: string;
  cwe?: string;
}

function normEndpoint(endpoint: string | undefined): string {
  if (!endpoint) return "";
  try {
    const u = new URL(endpoint);
    return `${u.protocol}//${u.hostname.toLowerCase()}${u.pathname}`.toLowerCase();
  } catch {
    return endpoint.toLowerCase();
  }
}

/**
 * FindingFingerprintService (§19): the canonical fingerprint deliberately
 * EXCLUDES the reporting tool — it keys on asset + service + endpoint +
 * parameter + vulnerability class + CVE/CWE, so Nuclei, Nikto, testssl.sh
 * and SSLyze reports of the same underlying issue produce the SAME
 * fingerprint and merge (§21). Deterministic: same inputs, same output.
 */
export function canonicalFindingFingerprint(input: FingerprintInput): string {
  const basis = [
    input.host.toLowerCase(),
    // When an endpoint URL is present it already implies the service port;
    // counting the port twice would split one issue into two findings
    // (e.g. Nuclei reports URL-only, Nikto reports host+port+URL).
    input.endpoint ? "" : input.port !== undefined ? String(input.port) : "",
    normEndpoint(input.endpoint),
    (input.parameter ?? "").toLowerCase(),
    input.vulnClass.toUpperCase(),
    (input.cve ?? input.cwe ?? "").toUpperCase(),
  ].join("|");
  return createHash("sha256").update(basis).digest("hex");
}

/** Per-source fingerprint: includes the tool (+ template/check id), so each
 *  contribution keeps its own stable identity inside a merged finding. */
export function sourceFindingFingerprint(input: FingerprintInput & { sourceTool: string; checkId?: string }): string {
  const basis = [
    input.sourceTool.toLowerCase(),
    input.checkId ?? "",
    input.host.toLowerCase(),
    input.port !== undefined ? String(input.port) : "",
    normEndpoint(input.endpoint),
    (input.parameter ?? "").toLowerCase(),
    input.vulnClass.toUpperCase(),
    (input.cve ?? input.cwe ?? "").toUpperCase(),
  ].join("|");
  return createHash("sha256").update(basis).digest("hex");
}

// ------------------------------- Confidence (§22/§23) -------------------------------

export type ConfidenceBand = "LOW" | "MEDIUM" | "HIGH" | "CONFIRMED";

export function confidenceBand(score: number): ConfidenceBand {
  if (score >= 0.95) return "CONFIRMED";
  if (score >= 0.7) return "HIGH";
  if (score >= 0.4) return "MEDIUM";
  return "LOW";
}

export interface ConfidenceSource {
  tool: string;
  confidence: number;
  signatureFamily?: string;
}

export interface ConfidenceAssessment {
  score: number;
  band: ConfidenceBand;
  verificationStatus: "UNVERIFIED" | "LIKELY" | "CONFIRMED" | "REJECTED";
  rationale: string[];
}

/**
 * Confidence model (§22). Base = strongest single source. Corroboration
 * adds +0.12 per ADDITIONAL INDEPENDENT tool — independent means a
 * different tool whose signature family differs (two tools relaying the
 * same upstream signature add nothing: §22's explicit warning). The
 * CONFIRMED band/status is reachable ONLY through deterministic
 * verification (a controlled check or manual validation), never merely
 * because several scanners agree.
 */
export function assessConfidence(input: {
  sources: ConfidenceSource[];
  deterministicVerification?: boolean;
}): ConfidenceAssessment {
  const rationale: string[] = [];
  const sources = [...input.sources].sort((a, b) => b.confidence - a.confidence);
  const base = sources[0]?.confidence ?? 0;
  rationale.push(`strongest source confidence ${base.toFixed(2)} (${sources[0]?.tool ?? "none"})`);

  const counted = new Set<string>();
  let independent = 0;
  for (const s of sources) {
    const family = s.signatureFamily ?? `tool:${s.tool}`;
    if (counted.has(family)) {
      rationale.push(`${s.tool} shares signature family "${family}" with an already-counted source — no corroboration bonus (§22)`);
      continue;
    }
    counted.add(family);
    independent++;
  }
  const extra = Math.max(0, independent - 1);
  let score = base + extra * 0.12;
  if (extra > 0) rationale.push(`+${(extra * 0.12).toFixed(2)} corroboration from ${extra} independent tool(s)`);

  if (input.deterministicVerification) {
    score = Math.max(score, 0.97);
    rationale.push("deterministic verification performed — CONFIRMED is justified");
  }
  score = Math.min(1, Math.round(score * 100) / 100);
  const band = confidenceBand(score);
  const verificationStatus = input.deterministicVerification && score >= 0.95
    ? "CONFIRMED"
    : score >= 0.6 ? "LIKELY" : "UNVERIFIED";
  if (verificationStatus !== "CONFIRMED") {
    rationale.push("automated detection alone never marks a finding CONFIRMED (§23)");
  }
  return { score, band, verificationStatus, rationale };
}

// ------------------------------- Risk engine (§34/§35/§36) -------------------------------

export type AssetCriticality = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNSPECIFIED";
export type RiskBand = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";

const SEVERITY_BASE: Record<Severity, number> = { CRITICAL: 95, HIGH: 75, MEDIUM: 50, LOW: 25, INFORMATIONAL: 5 };
const CRITICALITY_FACTOR: Record<string, number> = { CRITICAL: 1.15, HIGH: 1.08, MEDIUM: 1.0, LOW: 0.92, UNSPECIFIED: 1.0 };

export function riskBandForScore(score: number): RiskBand {
  if (score >= 90) return "CRITICAL";
  if (score >= 70) return "HIGH";
  if (score >= 40) return "MEDIUM";
  if (score >= 10) return "LOW";
  return "INFORMATIONAL";
}

/**
 * RiskEngine (§34/§35): score 0–100, fully explained.
 *   base       = CVSS base × 10 when a source actually provided a CVSS
 *                score, else the severity-band base (95/75/50/25/5)
 *   confidence = base scaled by (0.6 + 0.4 × confidence)
 *   context    = × asset-criticality factor; +5 when internet-exposed
 *   status     = CONFIRMED +3; REJECTED findings score 0
 * Scanner severity is an INPUT, never the final business risk (§24).
 */
export function computeRisk(input: {
  severity: Severity;
  cvssScore?: number;
  confidence: number;
  assetCriticality?: string;
  internetExposed?: boolean;
  verificationStatus?: string;
}): { score: number; band: RiskBand; explanation: string[] } {
  const explanation: string[] = [];
  if (input.verificationStatus === "REJECTED") {
    return { score: 0, band: "INFORMATIONAL", explanation: ["finding REJECTED in review — risk is 0"] };
  }
  let base: number;
  if (input.cvssScore !== undefined && Number.isFinite(input.cvssScore)) {
    base = input.cvssScore * 10;
    explanation.push(`base ${base} from source-provided CVSS ${input.cvssScore} × 10`);
  } else {
    base = SEVERITY_BASE[input.severity];
    explanation.push(`base ${base} from severity ${input.severity} (no CVSS provided by any source)`);
  }
  const confFactor = 0.6 + 0.4 * Math.min(1, Math.max(0, input.confidence));
  let score = base * confFactor;
  explanation.push(`confidence factor ${confFactor.toFixed(2)} (confidence ${input.confidence.toFixed(2)})`);
  const crit = input.assetCriticality ?? "UNSPECIFIED";
  const critFactor = CRITICALITY_FACTOR[crit] ?? 1.0;
  score *= critFactor;
  explanation.push(`asset criticality ${crit} × ${critFactor}`);
  if (input.internetExposed) { score += 5; explanation.push("+5 internet-exposed service"); }
  if (input.verificationStatus === "CONFIRMED") { score += 3; explanation.push("+3 manually/deterministically confirmed"); }
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, band: riskBandForScore(score), explanation };
}
