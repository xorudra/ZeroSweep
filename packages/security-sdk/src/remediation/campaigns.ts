import type { RemediationStatus } from "./types";

/**
 * Campaign progress (Prompt 31 §87–§91). Progress is computed from the
 * live case states every time — never stored counters that can drift.
 */
export interface CampaignProgress {
  total: number;
  assigned: number;
  inProgress: number;
  fixClaimed: number;
  verificationPending: number;
  verified: number;
  closed: number;
  overdue: number;
  exceptions: number;
  pctVerified: number;
}

export function computeCampaignProgress(
  cases: Array<{ status: RemediationStatus | string; dueAt: Date | null }>,
  now: Date,
): CampaignProgress {
  const progress: CampaignProgress = {
    total: cases.length, assigned: 0, inProgress: 0, fixClaimed: 0,
    verificationPending: 0, verified: 0, closed: 0, overdue: 0, exceptions: 0, pctVerified: 0,
  };
  for (const c of cases) {
    switch (c.status) {
      case "ASSIGNED": case "PLANNED": progress.assigned += 1; break;
      case "IN_PROGRESS": case "BLOCKED": case "REOPENED": progress.inProgress += 1; break;
      case "FIX_CLAIMED": progress.fixClaimed += 1; break;
      case "VERIFICATION_PENDING": case "VERIFICATION_RUNNING": progress.verificationPending += 1; break;
      case "VERIFIED_FIXED": progress.verified += 1; break;
      case "CLOSED": progress.closed += 1; progress.verified += 1; break;
      case "ACCEPTED_RISK": case "FALSE_POSITIVE": case "DEFERRED": progress.exceptions += 1; break;
      default: break;
    }
    const terminal = c.status === "CLOSED" || c.status === "VERIFIED_FIXED";
    if (!terminal && c.dueAt && c.dueAt.getTime() < now.getTime()) progress.overdue += 1;
  }
  progress.pctVerified = progress.total > 0 ? Math.round((progress.verified / progress.total) * 1000) / 10 : 0;
  return progress;
}

/** Campaign scope match (§87/§91): does a finding belong to the
 *  campaign scope? Scope keys are ANDed; absent keys match everything. */
export function findingMatchesCampaignScope(
  scope: { cve?: string; componentPurl?: string; product?: string; technology?: string; kevOnly?: boolean },
  finding: { cve?: string | null; componentPurl?: string | null; kevListed?: boolean; title?: string; sources?: string[] },
): boolean {
  if (scope.cve && finding.cve?.toUpperCase() !== scope.cve.toUpperCase()) return false;
  if (scope.componentPurl && finding.componentPurl !== scope.componentPurl) return false;
  if (scope.kevOnly && !finding.kevListed) return false;
  if (scope.product) {
    const haystack = `${finding.title ?? ""} ${(finding.sources ?? []).join(" ")}`.toLowerCase();
    if (!haystack.includes(scope.product.toLowerCase())) return false;
  }
  if (scope.technology) {
    const haystack = `${finding.title ?? ""} ${(finding.sources ?? []).join(" ")}`.toLowerCase();
    if (!haystack.includes(scope.technology.toLowerCase())) return false;
  }
  return true;
}
