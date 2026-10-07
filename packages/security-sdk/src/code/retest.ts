import type { NormalizedFinding } from "../findings/finding.types";

/**
 * Source finding retests (Prompt 12 §77). A retest re-scans the CURRENT
 * snapshot through the same governed pipeline and compares FINGERPRINTS:
 *  - SAST/secret finding absent from the new snapshot → RESOLVED;
 *  - still present → STILL_PRESENT (never "fixed" on a failed scan —
 *    the Phase 11 rule carries over: a failed stage judges nothing);
 *  - dependency findings resolve only when the component is upgraded
 *    past the fixed version or removed.
 * The planner is pure; execution goes through the ordinary scan DAG.
 */

export type SourceRetestKind = "SAST" | "SECRET" | "DEPENDENCY";

export interface SourceRetestPlan {
  kind: SourceRetestKind;
  /** The source profile the retest scan should use. */
  profile: "SAST_ONLY" | "SECRETS_ONLY" | "DEPENDENCIES_ONLY";
  fingerprint: string;
  componentPurl?: string;
  fixedVersion?: string;
}

export function planSourceRetest(finding: {
  sourceFingerprint: string;
  secret?: unknown;
  componentPurl?: string;
  fixedVersion?: string;
}): SourceRetestPlan {
  if (finding.secret) {
    return { kind: "SECRET", profile: "SECRETS_ONLY", fingerprint: finding.sourceFingerprint };
  }
  if (finding.componentPurl) {
    return {
      kind: "DEPENDENCY", profile: "DEPENDENCIES_ONLY", fingerprint: finding.sourceFingerprint,
      componentPurl: finding.componentPurl, fixedVersion: finding.fixedVersion,
    };
  }
  return { kind: "SAST", profile: "SAST_ONLY", fingerprint: finding.sourceFingerprint };
}

/** Compare two dotted versions numerically (best effort; non-numeric
 *  segments compare lexically). Returns -1 | 0 | 1. */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/, "").split(/[.-]/);
  const pb = b.replace(/^v/, "").split(/[.-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? "0";
    const y = pb[i] ?? "0";
    const nx = Number(x);
    const ny = Number(y);
    if (Number.isFinite(nx) && Number.isFinite(ny)) {
      if (nx !== ny) return nx < ny ? -1 : 1;
    } else if (x !== y) {
      return x < y ? -1 : 1;
    }
  }
  return 0;
}

export type SourceRetestOutcome = "RESOLVED" | "STILL_PRESENT" | "INCONCLUSIVE";

export function judgeSourceRetest(
  plan: SourceRetestPlan,
  rescan: { fingerprints: string[]; components: { purl: string; version?: string }[]; scanCompleted: boolean },
): { outcome: SourceRetestOutcome; detail: string } {
  if (!rescan.scanCompleted) {
    return { outcome: "INCONCLUSIVE", detail: "the retest scan did not complete — a failed scan never judges a finding resolved (§77)" };
  }
  if (plan.kind === "DEPENDENCY" && plan.componentPurl) {
    const current = rescan.components.find((c) => c.purl === plan.componentPurl || c.purl.startsWith(plan.componentPurl!.split("@")[0]));
    if (!current) return { outcome: "RESOLVED", detail: "component no longer present in the dependency inventory" };
    if (plan.fixedVersion && current.version && compareVersions(current.version, plan.fixedVersion) >= 0) {
      return { outcome: "RESOLVED", detail: `component upgraded to ${current.version} (>= fixed ${plan.fixedVersion})` };
    }
    if (!rescan.fingerprints.includes(plan.fingerprint)) {
      return { outcome: "RESOLVED", detail: "the dependency finding no longer reproduces" };
    }
    return { outcome: "STILL_PRESENT", detail: "component is still at a vulnerable version" };
  }
  return rescan.fingerprints.includes(plan.fingerprint)
    ? { outcome: "STILL_PRESENT", detail: "the finding reproduces in the current snapshot" }
    : { outcome: "RESOLVED", detail: "the finding no longer reproduces in the current snapshot" };
}

export type { NormalizedFinding };
