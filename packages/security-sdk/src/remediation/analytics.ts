/**
 * Remediation analytics (Prompt 31 §109–§111). Three distinct clocks —
 * Mean Time to Claim Fix, Mean Time to Verify Fix, Mean Time to Close —
 * documented formulas, computed from the append-only status history.
 * These are REMEDIATION metrics; the SOC's incident-response MTTR
 * (Prompt 28) is a different quantity and is never mixed in (§111).
 * Averages over an empty set are null — never fabricated zeroes.
 */

export interface CaseTimelineFacts {
  caseId: string;
  ownerId?: string | null;
  teamId?: string | null;
  createdAt: Date;
  /** Ordered status entry timestamps for this case. */
  entered: Partial<Record<string, Date>>;
  dueAt?: Date | null;
  slaBreached: boolean;
  regressionCount: number;
}

export interface RemediationMetrics {
  openBacklog: number;
  /** created → first FIX_CLAIMED, hours (§111). */
  meanTimeToClaimFixHours: number | null;
  /** first FIX_CLAIMED → VERIFIED_FIXED, hours (§111). */
  meanTimeToVerifyFixHours: number | null;
  /** created → CLOSED, hours (§111). */
  meanTimeToCloseHours: number | null;
  /** created → first assignment, hours (§110 time-to-assign). */
  meanTimeToAssignHours: number | null;
  /** closed-or-verified cases closed by dueAt / all closed-or-verified. */
  slaCompliancePct: number | null;
  /** FAILED verification jobs / all completed verification jobs. */
  verificationFailureRate: number | null;
  /** cases with ≥1 regression / cases ever verified fixed. */
  regressionRate: number | null;
  /** cases with an approved exception / all cases. */
  exceptionRate: number | null;
}

function meanHours(durationsMs: number[]): number | null {
  if (durationsMs.length === 0) return null;
  const mean = durationsMs.reduce((a, b) => a + b, 0) / durationsMs.length;
  return Math.round((mean / 3600000) * 100) / 100;
}

export function computeRemediationMetrics(input: {
  cases: CaseTimelineFacts[];
  verificationOutcomes: Array<"PASSED" | "FAILED" | "INCONCLUSIVE" | "ERROR">;
  exceptionCaseIds: Set<string> | string[];
}): RemediationMetrics {
  const claimDurations: number[] = [];
  const verifyDurations: number[] = [];
  const closeDurations: number[] = [];
  const assignDurations: number[] = [];
  let openBacklog = 0;
  let slaEligible = 0;
  let slaMet = 0;
  let everVerified = 0;
  let regressed = 0;
  const exceptionSet = new Set(input.exceptionCaseIds);
  const terminal = new Set(["CLOSED", "VERIFIED_FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK"]);

  for (const c of input.cases) {
    const claimed = c.entered["FIX_CLAIMED"];
    const verified = c.entered["VERIFIED_FIXED"];
    const closed = c.entered["CLOSED"];
    const assigned = c.entered["ASSIGNED"];
    if (!closed && ![...terminal].some((t) => c.entered[t])) openBacklog += 1;
    if (assigned) assignDurations.push(assigned.getTime() - c.createdAt.getTime());
    if (claimed) claimDurations.push(claimed.getTime() - c.createdAt.getTime());
    if (claimed && verified) verifyDurations.push(verified.getTime() - claimed.getTime());
    if (closed) closeDurations.push(closed.getTime() - c.createdAt.getTime());
    if (verified || closed) {
      everVerified += 1;
      if (c.regressionCount > 0) regressed += 1;
      if (c.dueAt) {
        slaEligible += 1;
        const doneAt = closed ?? verified!;
        if (doneAt.getTime() <= c.dueAt.getTime() && !c.slaBreached) slaMet += 1;
      }
    }
  }

  const completed = input.verificationOutcomes.filter((o) => o === "PASSED" || o === "FAILED");
  const failed = input.verificationOutcomes.filter((o) => o === "FAILED").length;
  return {
    openBacklog,
    meanTimeToClaimFixHours: meanHours(claimDurations),
    meanTimeToVerifyFixHours: meanHours(verifyDurations),
    meanTimeToCloseHours: meanHours(closeDurations),
    meanTimeToAssignHours: meanHours(assignDurations),
    slaCompliancePct: slaEligible > 0 ? Math.round((slaMet / slaEligible) * 1000) / 10 : null,
    verificationFailureRate: completed.length > 0 ? Math.round((failed / completed.length) * 1000) / 1000 : null,
    regressionRate: everVerified > 0 ? Math.round((regressed / everVerified) * 1000) / 1000 : null,
    exceptionRate: input.cases.length > 0 ? Math.round((exceptionSet.size / input.cases.length) * 1000) / 1000 : null,
  };
}

/** Fix durability (§77): hours from verified fix to regression, per
 *  case that regressed. Null when nothing has regressed. */
export function fixDurabilityHours(events: Array<{ verifiedFixedAt: Date; regressedAt: Date }>): number | null {
  if (events.length === 0) return null;
  const durations = events.map((e) => e.regressedAt.getTime() - e.verifiedFixedAt.getTime());
  return meanHours(durations);
}
