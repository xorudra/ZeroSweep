/**
 * Network VAPT coverage + completion honesty (Prompt 33 §121–§123).
 *
 * Coverage is computed from what ACTUALLY ran: authorized hosts vs
 * discovered vs scanned, port/service/vulnerability-scanner coverage,
 * credentialed coverage where applicable. Every gap is a recorded
 * limitation with a reason. A scan with incomplete coverage reports
 * COMPLETED_WITH_GAPS — it must not appear fully complete (§123),
 * and a scanner failure is a gap, never a clean result (§155).
 */

export interface NetworkCoverageInput {
  authorizedHosts: number;
  discoveredHosts: number;
  scannedHosts: number;
  hostsWithPortScan: number;
  hostsWithServiceDetection: number;
  /** null when no vulnerability scanner was part of the profile. */
  hostsWithVulnScan: number | null;
  /** null when the profile is not credentialed. */
  hostsWithCredentialedScan: number | null;
  /** Named limitations (§122): unreachable, filtered, scanner down,
   *  auth failed, budget exhausted, policy blocked… */
  limitations: string[];
  stageOutcomes: Array<{ stage: string; status: "COMPLETED" | "PARTIAL" | "FAILED" | "SKIPPED" }>;
}

export interface NetworkVaptCoverageResult {
  authorizedHosts: number;
  discoveredHosts: number;
  scannedHosts: number;
  portCoveragePct: number | null;
  serviceCoveragePct: number | null;
  vulnScannerCoveragePct: number | null;
  credentialedCoveragePct: number | null;
  limitations: string[];
  /** §123: the honest completion label for the scan. */
  completion: "COMPLETED" | "COMPLETED_WITH_GAPS" | "PARTIAL" | "FAILED";
  /** Never 100 unless every planned dimension actually ran. */
  fullyCovered: boolean;
}

function pct(part: number, whole: number): number | null {
  if (whole <= 0) return null;
  return Math.round((part / whole) * 1000) / 10;
}

export function computeNetworkCoverage(input: NetworkCoverageInput): NetworkVaptCoverageResult {
  const limitations = [...input.limitations];
  const denom = Math.max(input.scannedHosts, 0);
  const portCoveragePct = pct(input.hostsWithPortScan, denom);
  const serviceCoveragePct = pct(input.hostsWithServiceDetection, denom);
  const vulnScannerCoveragePct = input.hostsWithVulnScan === null ? null : pct(input.hostsWithVulnScan, denom);
  const credentialedCoveragePct = input.hostsWithCredentialedScan === null ? null : pct(input.hostsWithCredentialedScan, denom);

  if (input.discoveredHosts > 0 && input.scannedHosts < input.discoveredHosts) {
    limitations.push(`${input.discoveredHosts - input.scannedHosts} discovered host(s) were not scanned (scope/budget) (§121)`);
  }
  if (vulnScannerCoveragePct !== null && vulnScannerCoveragePct < 100) {
    limitations.push(`Vulnerability-scanner coverage ${vulnScannerCoveragePct}% — un-scanned hosts are UNKNOWN, not clean (§122/§155)`);
  }
  const anyStageFailed = input.stageOutcomes.some((s) => s.status === "FAILED");
  const anyStagePartial = input.stageOutcomes.some((s) => s.status === "PARTIAL" || s.status === "SKIPPED");

  const fullyCovered = limitations.length === 0 && !anyStageFailed && !anyStagePartial
    && (portCoveragePct === 100) && (serviceCoveragePct === 100)
    && (vulnScannerCoveragePct === null || vulnScannerCoveragePct === 100)
    && (credentialedCoveragePct === null || credentialedCoveragePct === 100)
    && input.scannedHosts >= input.discoveredHosts && input.discoveredHosts > 0;

  const completion: NetworkVaptCoverageResult["completion"] = anyStageFailed && input.scannedHosts === 0
    ? "FAILED"
    : anyStageFailed || anyStagePartial
      ? "PARTIAL"
      : fullyCovered ? "COMPLETED" : "COMPLETED_WITH_GAPS";

  return {
    authorizedHosts: input.authorizedHosts, discoveredHosts: input.discoveredHosts, scannedHosts: input.scannedHosts,
    portCoveragePct, serviceCoveragePct, vulnScannerCoveragePct, credentialedCoveragePct,
    limitations, completion, fullyCovered,
  };
}
