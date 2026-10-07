/**
 * Prompt 18 — binary retest planning (§57/§84-adjacent, P11 §56
 * discipline).
 *
 * A binary retest is ARTIFACT-OVER-ARTIFACT: the finding was observed
 * on artifact A; the fix ships as artifact B (a new SHA-256); the
 * retest re-runs the targeted static check against the NEW artifact
 * and compares §57 binary fingerprints, which deliberately exclude
 * the artifact hash (lineage + component + rule + location). The
 * original finding is never edited — RESOLVED / REOPENED is judged
 * from fresh evidence, and a retest that cannot run is FAILED,
 * never a pass.
 */
export interface BinaryRetestPlan {
  stageType: "BINARY_HARDENING_ANALYSIS" | "BINARY_STATIC_ANALYSIS";
  adapterSlug: string;
  reason: string;
}

export function planBinaryRetest(input: { ruleId?: string; sourceTool?: string; binaryFindingType?: string }): BinaryRetestPlan {
  if (input.sourceTool === "checksec" || input.binaryFindingType === "BINARY_HARDENING_FINDING") {
    return {
      stageType: "BINARY_HARDENING_ANALYSIS", adapterSlug: "checksec",
      reason: "hardening findings retest through a fresh checksec analysis of the NEW artifact",
    };
  }
  if (input.sourceTool === "radare2") {
    return {
      stageType: "BINARY_STATIC_ANALYSIS", adapterSlug: "radare2",
      reason: "radare2 findings retest through the typed static analysis of the NEW artifact",
    };
  }
  return {
    stageType: "BINARY_STATIC_ANALYSIS", adapterSlug: "ghidra",
    reason: "static/dependency/secret findings retest through the Ghidra static inventory of the NEW artifact",
  };
}
