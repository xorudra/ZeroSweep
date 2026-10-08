/**
 * Security baseline classification (Prompt 24 §40, §41, §121, §122).
 *
 * A baseline is an IMMUTABLE fingerprint set captured at a specific
 * commit + snapshot (§41). Classification is set arithmetic only:
 *
 * - fingerprint in baseline, still present          → PRE_EXISTING
 * - fingerprint absent from baseline, present now,
 *   and previously resolved after the baseline     → REGRESSED
 * - fingerprint absent from baseline, present now    → NEW
 * - fingerprint in baseline, absent now              → RESOLVED
 *
 * §121: a pre-existing high finding the PR does not touch is
 * PRE_EXISTING, never NEW. §122: a fingerprint that was resolved and
 * reappears is REGRESSED (the finding reopens), never silently NEW.
 */

export type BaselineClassification = "NEW" | "PRE_EXISTING" | "REGRESSED";

export interface BaselineClassificationResult {
  perFinding: Array<{ fingerprint: string; classification: BaselineClassification }>;
  newFingerprints: string[];
  preExistingFingerprints: string[];
  regressedFingerprints: string[];
  /** In the baseline but absent now — resolved since the baseline. */
  resolvedFingerprints: string[];
}

export function classifyAgainstBaseline(input: {
  baselineFingerprints: string[];
  currentFingerprints: string[];
  /** Fingerprints resolved at any point after the baseline was taken. */
  previouslyResolvedFingerprints?: string[];
}): BaselineClassificationResult {
  const baseline = new Set(input.baselineFingerprints);
  const current = new Set(input.currentFingerprints);
  const resolvedBefore = new Set(input.previouslyResolvedFingerprints ?? []);
  const perFinding: BaselineClassificationResult["perFinding"] = [];
  const newFingerprints: string[] = [];
  const preExistingFingerprints: string[] = [];
  const regressedFingerprints: string[] = [];
  for (const fp of current) {
    let classification: BaselineClassification;
    if (resolvedBefore.has(fp)) classification = "REGRESSED";
    else if (baseline.has(fp)) classification = "PRE_EXISTING";
    else classification = "NEW";
    perFinding.push({ fingerprint: fp, classification });
    if (classification === "NEW") newFingerprints.push(fp);
    else if (classification === "PRE_EXISTING") preExistingFingerprints.push(fp);
    else regressedFingerprints.push(fp);
  }
  const resolvedFingerprints = [...baseline].filter((fp) => !current.has(fp));
  return { perFinding, newFingerprints, preExistingFingerprints, regressedFingerprints, resolvedFingerprints };
}
