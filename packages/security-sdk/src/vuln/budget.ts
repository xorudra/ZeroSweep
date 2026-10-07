/**
 * Vulnerability-scan budget (Prompt 7 §8/§51/§52). Extends the Prompt 5/6
 * discovery budgets with vulnerability-stage ceilings. Administrators set
 * hard caps; profiles may only request LOWER values. Rate limits here are
 * the values adapters must clamp to — scanner vendor defaults never win
 * over platform policy (§52).
 */
export interface VulnBudget {
  /** Total requests a vulnerability stage may issue (§51). */
  maxVulnerabilityRequests: number;
  /** Nuclei templates selected per scan (§8). */
  maxNucleiTemplates: number;
  /** Requests/sec ceiling handed to Nuclei (§8/§52). */
  nucleiRequestsPerSecond: number;
  /** Nuclei concurrency ceiling (§8). */
  nucleiConcurrency: number;
  /** Nikto wall-clock ceiling, seconds (§51). */
  maxNiktoDurationSeconds: number;
  /** TLS services assessed per scan (§51). */
  maxTlsServices: number;
  /** Per-item evidence cap, bytes (§31/§51). */
  maxEvidenceSizeBytes: number;
  /** Canonical findings cap per scan; reaching it is a RECORDED event,
   *  never a silent discard (§51). */
  maxFindings: number;
}

export const DEFAULT_VULN_BUDGET: VulnBudget = {
  maxVulnerabilityRequests: 5_000,
  maxNucleiTemplates: 200,
  nucleiRequestsPerSecond: 50,
  nucleiConcurrency: 10,
  maxNiktoDurationSeconds: 1_800,
  maxTlsServices: 25,
  maxEvidenceSizeBytes: 256 * 1024,
  maxFindings: 1_000,
};

export const ADMIN_VULN_CAPS: VulnBudget = {
  maxVulnerabilityRequests: 50_000,
  maxNucleiTemplates: 2_000,
  nucleiRequestsPerSecond: 150,
  nucleiConcurrency: 25,
  maxNiktoDurationSeconds: 7_200,
  maxTlsServices: 200,
  maxEvidenceSizeBytes: 1024 * 1024,
  maxFindings: 10_000,
};

const KEYS = Object.keys(DEFAULT_VULN_BUDGET) as (keyof VulnBudget)[];

export function clampVulnBudget(requested: Partial<VulnBudget> = {}): VulnBudget {
  const out = { ...DEFAULT_VULN_BUDGET };
  for (const key of KEYS) {
    const v = requested[key];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      out[key] = Math.min(Math.floor(v), ADMIN_VULN_CAPS[key]);
    }
  }
  return out;
}
