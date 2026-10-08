/**
 * Network risk signals for Risk Engine V3 (Prompt 33 §108/§109).
 *
 * The contextual score is a WEIGHTED SIGNAL COMPOSITION — internet
 * exposure, zone, asset criticality, service sensitivity, CVE severity,
 * KEV presence, EPSS, verification confidence, scanner agreement and
 * patch availability — never CVSS alone. EPSS is null-never-0 (the
 * Prompt 30 rule): unknown exploit probability contributes nothing and
 * is reported as unknown, not as zero risk.
 */

export interface NetworkRiskSignals {
  cvssScore?: number;
  kevListed?: boolean;
  /** Prompt 30 rule: unknown EPSS is null, never 0. */
  epssScore?: number | null;
  internetExposed: boolean;
  zone: "INTERNET" | "DMZ" | "INTERNAL" | "RESTRICTED" | "MANAGEMENT" | "UNKNOWN";
  assetCriticality: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNSPECIFIED";
  sensitiveService: boolean;
  confidenceBand: "LOW" | "MEDIUM" | "HIGH" | "VERIFIED";
  scannersAgreeing: number;
  patchAvailable?: boolean;
  cveAttribution: "CONFIRMED" | "UNCERTAIN" | "NONE";
}

export interface NetworkRiskAssessment {
  /** 0..100 contextual priority score (deterministic). */
  score: number;
  band: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /** Human-readable composition — every point accounted for (§109). */
  explanation: string[];
}

export function assessNetworkRisk(signals: NetworkRiskSignals): NetworkRiskAssessment {
  const explanation: string[] = [];
  let score = 0;

  const cvssContribution = typeof signals.cvssScore === "number" ? Math.min(40, signals.cvssScore * 4) : 0;
  if (cvssContribution > 0) { score += cvssContribution; explanation.push(`CVSS ${signals.cvssScore} contributes ${cvssContribution}/40 — one signal among many, never the whole priority (§109)`); }
  else explanation.push("No CVSS available — priority rests on contextual signals (§109)");

  if (signals.kevListed) { score += 15; explanation.push("CVE is in CISA KEV (known-exploited) +15"); }
  if (typeof signals.epssScore === "number") {
    const epssPoints = Math.round(signals.epssScore * 10);
    score += epssPoints; explanation.push(`EPSS ${(signals.epssScore * 100).toFixed(1)}% contributes +${epssPoints}`);
  } else {
    explanation.push("EPSS unknown (null, never treated as 0) — contributes nothing (§108)");
  }
  if (signals.internetExposed) { score += 12; explanation.push("Internet-exposed +12 (§97)"); }
  const zonePoints = { INTERNET: 10, DMZ: 6, INTERNAL: 2, RESTRICTED: 0, MANAGEMENT: 4, UNKNOWN: 3 }[signals.zone];
  if (zonePoints > 0) { score += zonePoints; explanation.push(`Zone ${signals.zone} +${zonePoints}`); }
  const critPoints = { CRITICAL: 10, HIGH: 6, MEDIUM: 3, LOW: 1, UNSPECIFIED: 0 }[signals.assetCriticality];
  if (critPoints > 0) { score += critPoints; explanation.push(`Asset criticality ${signals.assetCriticality} +${critPoints}`); }
  if (signals.sensitiveService) { score += 6; explanation.push("Sensitive service class (§98) +6"); }
  const confPoints = { VERIFIED: 8, HIGH: 5, MEDIUM: 2, LOW: 0 }[signals.confidenceBand];
  if (confPoints > 0) { score += confPoints; explanation.push(`Verification confidence ${signals.confidenceBand} +${confPoints}`); }
  if (signals.scannersAgreeing > 1) { score += 4; explanation.push(`${signals.scannersAgreeing} scanners agree +4 (§69)`); }
  if (signals.patchAvailable) { score += 3; explanation.push("Patch available — fixable now, prioritized for remediation (+3 actionability)"); }
  if (signals.cveAttribution === "UNCERTAIN") {
    score = Math.min(score, 45);
    explanation.push("CVE attribution is UNCERTAIN (banner-only evidence) — score capped until confirmed (§68/§147)");
  }

  score = Math.max(0, Math.min(100, Math.round(score)));
  const band = score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  return { score, band, explanation };
}
