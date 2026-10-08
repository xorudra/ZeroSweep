import type { SkippedReason, WebVaptScanStatus } from "./types";

/**
 * Coverage + tool health (Prompt 32 §146–§151).
 *
 * Coverage is an honest accounting of what was actually tested —
 * discovered vs tested endpoints, parameter and authenticated
 * coverage, which tools contributed, and WHY each skipped test was
 * skipped. A completed scan NEVER claims the target is "100% secure"
 * (§148): the coverage record is the limitations section of the
 * report, computed from the same numbers.
 */

export interface SkippedTest {
  test: string;
  reason: SkippedReason;
  detail?: string;
}

export interface WebVaptCoverageInput {
  discoveredEndpoints: number;
  testedEndpoints: number;
  discoveredParameters: number;
  testedParameters: number;
  authenticatedEndpoints: number;
  testedAuthenticatedEndpoints: number;
  toolsPlanned: string[];
  toolsContributed: string[];
  skipped: SkippedTest[];
  budgetExhausted: boolean;
  stagesFailed: number;
}

export interface CoverageReport {
  discoveredEndpoints: number;
  testedEndpoints: number;
  endpointCoverage: number | null;
  parameterCoverage: number | null;
  authenticatedCoverage: number | null;
  toolCoverage: { planned: string[]; contributed: string[]; silent: string[] };
  skipped: SkippedTest[];
  /** §148: limitations wording for reports — never a security claim. */
  limitations: string[];
}

function ratio(tested: number, discovered: number): number | null {
  if (discovered <= 0) return null;
  return Math.round((Math.min(tested, discovered) / discovered) * 10_000) / 10_000;
}

export function computeCoverage(input: WebVaptCoverageInput): CoverageReport {
  const limitations: string[] = [];
  if (input.budgetExhausted) limitations.push("Request budget exhausted — active stages stopped gracefully (§186).");
  if (input.stagesFailed > 0) limitations.push(`${input.stagesFailed} stage(s) failed or were partial — their surface is untested, not clean (§145).`);
  for (const s of input.skipped) limitations.push(`Skipped ${s.test}: ${s.reason}${s.detail ? ` — ${s.detail}` : ""}`);
  if (input.discoveredEndpoints === 0) limitations.push("No endpoints were discovered — coverage is undefined, not complete.");
  const silent = input.toolsPlanned.filter((t) => !input.toolsContributed.includes(t));
  return {
    discoveredEndpoints: input.discoveredEndpoints,
    testedEndpoints: input.testedEndpoints,
    endpointCoverage: ratio(input.testedEndpoints, input.discoveredEndpoints),
    parameterCoverage: ratio(input.testedParameters, input.discoveredParameters),
    authenticatedCoverage: ratio(input.testedAuthenticatedEndpoints, input.authenticatedEndpoints),
    toolCoverage: { planned: input.toolsPlanned, contributed: input.toolsContributed, silent },
    skipped: input.skipped,
    limitations,
  };
}

/** §150/§151: derive the honest terminal status of a V2 scan. */
export function deriveScanStatus(input: { cancelled: boolean; preflightBlocked: boolean; stagesFailed: number; budgetExhausted: boolean; skippedCount: number }): WebVaptScanStatus {
  if (input.cancelled) return "CANCELLED";
  if (input.preflightBlocked) return "BLOCKED";
  if (input.stagesFailed > 0 && input.skippedCount === 0 && !input.budgetExhausted) return "FAILED";
  if (input.budgetExhausted || input.skippedCount > 0 || input.stagesFailed > 0) return "COMPLETED_WITH_GAPS";
  return "COMPLETED";
}

/* ------------------------------ tool health (§146) ------------------------------ */

export interface ToolHealthRecord {
  slug: string;
  installed: boolean;
  version?: string;
  lastSuccessfulRun?: string;
  errorRate: number;
  parserCompatible: boolean;
}

export interface ToolHealthView extends ToolHealthRecord {
  status: "HEALTHY" | "UNAVAILABLE" | "DEGRADED";
  detail: string;
}

export function toolHealthView(record: ToolHealthRecord): ToolHealthView {
  if (!record.installed) {
    return { ...record, status: "UNAVAILABLE", detail: "binary not present in this deployment — health reported honestly, never faked (§146)" };
  }
  if (!record.parserCompatible) {
    return { ...record, status: "DEGRADED", detail: "installed version's output is not parser-compatible — results would be partial (§144)" };
  }
  if (record.errorRate > 0.25) {
    return { ...record, status: "DEGRADED", detail: `elevated error rate ${(record.errorRate * 100).toFixed(0)}% across recent runs` };
  }
  return { ...record, status: "HEALTHY", detail: record.version ? `version ${record.version}` : "available" };
}
