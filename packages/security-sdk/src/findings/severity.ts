import type { Severity } from "@zerosweep/types";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
export const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 };

/** Map a CVSS base score to a severity band. Unknown scores stay undefined —
 *  the SDK never invents a CVSS/CVE/CWE for a finding. */
export function severityFromCvss(score: number | undefined): Severity | undefined {
  if (score === undefined || Number.isNaN(score)) return undefined;
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFORMATIONAL";
}
