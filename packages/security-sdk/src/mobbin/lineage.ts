import type { CarryForwardEntry, CarryForwardFindingRef, CarryForwardResult } from "./types";

/**
 * Prompt 35 §104–§108/§156/§157 — version lineage carry-forward.
 *
 * Identity across builds is the cross-build fingerprint (§104:
 * app + artifact lineage + component/location + rule). The
 * classification is deliberately conservative:
 * - present in both builds          → PERSISTING
 * - present only in the new build   → NEW
 * - present only in the old build   → FIXED_CANDIDATE — a hypothesis
 *   for Prompt 31 verification, NEVER a fix (§108: a new version
 *   does not automatically mean old findings are fixed; §107:
 *   closure needs the targeted retest against the new build)
 * - absent in an intermediate build (or verified RESOLVED) and
 *   present again now                → REGRESSED (§157), linked back
 *   to the Prompt 31 regression machinery by the caller.
 */
const CLOSED_STATUSES = new Set(["RESOLVED", "VERIFIED_FIXED", "CLOSED"]);

export function compareBuildFindings(input: {
  previous: CarryForwardFindingRef[];
  current: CarryForwardFindingRef[];
  /** Cross-build fingerprints seen in ANY earlier build before
   *  `previous` (with a gap in `previous`) — regression evidence. */
  earlierAbsent?: Set<string>;
}): CarryForwardResult {
  const prev = new Map(input.previous.map((f) => [f.crossBuildFingerprint, f]));
  const cur = new Map(input.current.map((f) => [f.crossBuildFingerprint, f]));
  const entries: CarryForwardEntry[] = [];

  for (const [fp, f] of cur) {
    const before = prev.get(fp);
    if (before) {
      entries.push({
        crossBuildFingerprint: fp, classification: "PERSISTING",
        fromFindingId: before.findingId, toFindingId: f.findingId,
        ruleId: f.ruleId, title: f.title, severity: f.severity, verification: null,
      });
    } else if (input.earlierAbsent?.has(fp)) {
      entries.push({
        crossBuildFingerprint: fp, classification: "REGRESSED",
        fromFindingId: null, toFindingId: f.findingId,
        ruleId: f.ruleId, title: f.title, severity: f.severity, verification: null,
      });
    } else {
      entries.push({
        crossBuildFingerprint: fp, classification: "NEW",
        fromFindingId: null, toFindingId: f.findingId,
        ruleId: f.ruleId, title: f.title, severity: f.severity, verification: null,
      });
    }
  }
  for (const [fp, f] of prev) {
    if (cur.has(fp)) continue;
    const wasClosed = CLOSED_STATUSES.has(f.status);
    entries.push({
      crossBuildFingerprint: fp,
      // An issue that was closed/verified and is simply absent stays
      // a FIXED_CANDIDATE for the record — absence alone never
      // upgrades anything to verified (§107/§108).
      classification: "FIXED_CANDIDATE",
      fromFindingId: f.findingId, toFindingId: null,
      ruleId: f.ruleId, title: f.title, severity: f.severity,
      verification: wasClosed ? null : "TARGETED_RETEST_REQUIRED",
    });
  }

  const summary = { NEW: 0, PERSISTING: 0, FIXED_CANDIDATE: 0, REGRESSED: 0 } as CarryForwardResult["summary"];
  for (const e of entries) summary[e.classification] += 1;
  return { entries, summary };
}
