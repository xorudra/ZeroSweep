/**
 * Prompt 17 — mobile retest planning (§89).
 *
 * A mobile retest is BUILD-OVER-BUILD: the finding was observed on
 * Build A; the fix ships in Build B; the retest re-runs the targeted
 * static check against BUILD B's registered artifacts and compares
 * cross-build identities. The original finding is never edited —
 * RESOLVED / REOPENED is judged from Build B evidence, and a retest
 * that cannot run is FAILED, never a pass (§58 discipline).
 */
export interface MobileRetestPlan {
  stageType: "MOBILE_STATIC_ANALYSIS" | "MOBILE_BINARY_ANALYSIS";
  adapterSlug: string;
  reason: string;
}

export function planMobileRetest(input: { ruleId?: string; sourceTool?: string; mobileFindingType?: string }): MobileRetestPlan {
  const ruleId = input.ruleId ?? "";
  if (input.mobileFindingType === "MOBILE_BINARY_FINDING" || ruleId.startsWith("MOBILE_BINARY_") || input.sourceTool === "ghidra") {
    return {
      stageType: "MOBILE_BINARY_ANALYSIS", adapterSlug: "ghidra",
      reason: "binary findings retest through the Ghidra static analysis of the NEW build (§89)",
    };
  }
  if (input.sourceTool === "mobsf") {
    return {
      stageType: "MOBILE_STATIC_ANALYSIS", adapterSlug: "mobsf",
      reason: "MobSF findings retest through a fresh MobSF static analysis of the NEW build (§89)",
    };
  }
  if (input.sourceTool === "jadx" || ruleId === "MOBILE_HARDCODED_SECRET") {
    return {
      stageType: "MOBILE_STATIC_ANALYSIS", adapterSlug: "jadx",
      reason: "code/secret findings retest through decompilation + pattern/secret analysis of the NEW build (§89)",
    };
  }
  return {
    stageType: "MOBILE_STATIC_ANALYSIS", adapterSlug: "apktool",
    reason: "manifest/configuration findings retest through manifest + platform analysis of the NEW build (§89)",
  };
}
