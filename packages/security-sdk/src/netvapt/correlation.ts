import type { NetworkFindingCandidate } from "./vuln-scanners";
import type { NetworkConfidenceBand } from "./types";

/**
 * Multi-scanner correlation (Prompt 33 §68–§71, §146/§147).
 *
 * - Same issue from Nessus + OpenVAS + Nmap ⇒ ONE canonical finding
 *   with multiple observations (§69), keyed by the §65 fingerprint.
 * - Disagreement is PRESERVED (§70): every scanner's severity stays on
 *   the record; the canonical severity comes from the highest-
 *   confidence observation, never blindly the highest severity.
 * - Confidence bands (§71): agreement raises confidence; a lone
 *   BANNER_ONLY attribution can never exceed MEDIUM and can never
 *   produce a CONFIRMED CVE (§68/§147 — weak banner similarity is not
 *   vulnerability evidence).
 */

export interface CanonicalNetworkFinding {
  fingerprint: string;
  assetHost: string;
  port?: number;
  transport: string;
  title: string;
  severity: NetworkFindingCandidate["severity"];
  /** Every contributing observation, verbatim (§70). */
  observations: Array<{
    scanner: string;
    pluginId: string;
    severity: NetworkFindingCandidate["severity"];
    confidence: number;
    title: string;
    evidence: string;
    observedAt: string;
  }>;
  cve?: string;
  cwe?: string;
  /** CVE attribution state (§68): only SCANNER_CONFIRMED evidence with
   *  a scanner-reported CPE or plugin identity confirms a CVE. */
  cveAttribution: "CONFIRMED" | "UNCERTAIN" | "NONE";
  confidence: number;
  confidenceBand: NetworkConfidenceBand;
  /** §70: scanners disagreed on severity — shown, never hidden. */
  severityDisagreement: boolean;
  scannersAgreeing: number;
}

const SEVERITY_RANK: Record<string, number> = { INFORMATIONAL: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

function bandOf(confidence: number): NetworkConfidenceBand {
  if (confidence >= 0.95) return "VERIFIED";
  if (confidence >= 0.75) return "HIGH";
  if (confidence >= 0.45) return "MEDIUM";
  return "LOW";
}

export function correlateNetworkFindings(candidates: NetworkFindingCandidate[]): CanonicalNetworkFinding[] {
  const groups = new Map<string, NetworkFindingCandidate[]>();
  for (const c of candidates) {
    const list = groups.get(c.fingerprint) ?? [];
    list.push(c);
    groups.set(c.fingerprint, list);
  }
  const out: CanonicalNetworkFinding[] = [];
  for (const [fingerprint, group] of groups) {
    const first = group[0]!;
    // Canonical severity: from the highest-confidence observation (§70).
    const byConfidence = [...group].sort((a, b) => b.confidence - a.confidence);
    const primary = byConfidence[0]!;
    const severities = new Set(group.map((g) => g.severity));
    // Confidence (§71): base = best observation; agreement among
    // independent scanners raises it; BANNER_ONLY caps at MEDIUM.
    const distinctScanners = new Set(group.map((g) => g.plugin.scanner));
    let confidence = primary.confidence;
    if (distinctScanners.size > 1) confidence = Math.min(0.97, confidence + 0.08 * (distinctScanners.size - 1));
    const allBannerOnly = group.every((g) => g.versionEvidence === "BANNER_ONLY");
    if (allBannerOnly) confidence = Math.min(confidence, 0.6);
    // CVE attribution (§68/§147).
    const cve = group.find((g) => g.cve)?.cve;
    const anyConfirmed = group.some((g) => g.versionEvidence === "SCANNER_CONFIRMED");
    const cveAttribution: CanonicalNetworkFinding["cveAttribution"] = !cve ? "NONE" : anyConfirmed ? "CONFIRMED" : "UNCERTAIN";
    if (cveAttribution === "UNCERTAIN") confidence = Math.min(confidence, 0.6);
    out.push({
      fingerprint,
      assetHost: first.assetHost,
      ...(typeof first.port === "number" ? { port: first.port } : {}),
      transport: first.transport,
      title: primary.title,
      severity: primary.severity,
      observations: group.map((g) => ({
        scanner: g.plugin.scanner, pluginId: g.plugin.pluginId, severity: g.severity,
        confidence: g.confidence, title: g.title, evidence: g.evidence, observedAt: g.observedAt,
      })),
      ...(cve ? { cve } : {}),
      ...(group.find((g) => g.cwe) ? { cwe: group.find((g) => g.cwe)!.cwe } : {}),
      cveAttribution,
      confidence,
      confidenceBand: bandOf(confidence),
      severityDisagreement: severities.size > 1,
      scannersAgreeing: distinctScanners.size,
    });
  }
  // Deterministic order: severity (desc), then fingerprint.
  return out.sort((a, b) => (SEVERITY_RANK[b.severity]! - SEVERITY_RANK[a.severity]!) || a.fingerprint.localeCompare(b.fingerprint));
}
