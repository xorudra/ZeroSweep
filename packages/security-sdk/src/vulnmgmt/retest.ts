import { canonicalFindingFingerprint } from "../vuln/analysis";

/**
 * Targeted retest planning (Prompt 11 §55–§58). A retest NEVER reruns a
 * whole assessment when the original safe detection mechanism suffices
 * (§56): the plan reuses the finding's source tool + check reference +
 * asset/service/endpoint, and execution must re-pass the SAME
 * authorization / scope / policy / budget controls as the original scan
 * (§57) — the executor enforces that; this module derives WHAT to run
 * and how to judge the outcome. Previous and new evidence are both
 * preserved in the retest record (§58).
 */

export interface RetestSourceFinding {
  fingerprint?: string | null;
  host?: string | null;
  port?: number | null;
  endpoint?: string | null;
  parameter?: string | null;
  vulnClass?: string | null;
  cve?: string | null;
  cwe?: string | null;
  sources: string[];
  /** Check reference (template/plugin id) from the finding's evidence metadata. */
  checkReference?: string | null;
  lifecycleStatus: string;
}

export interface RetestPlan {
  /** The original detection tool to re-run (first recorded source). */
  sourceTool: string;
  checkReference?: string;
  /** Canonical fingerprint the retest outcome is judged against. */
  canonicalFingerprint: string;
  target: { host?: string; port?: number; endpoint?: string };
  /** Why this plan is safe to execute as a targeted check. */
  rationale: string[];
}

export type RetestPlanResult = { ok: true; plan: RetestPlan } | { ok: false; error: string };

const RETESTABLE_LIFECYCLES = new Set(["REMEDIATED", "RETEST_PENDING", "CONFIRMED", "IN_PROGRESS"]);

export function planRetest(finding: RetestSourceFinding): RetestPlanResult {
  if (!RETESTABLE_LIFECYCLES.has(finding.lifecycleStatus)) {
    return { ok: false, error: `finding in lifecycle ${finding.lifecycleStatus} cannot be retested — remediate it first (§55)` };
  }
  const sourceTool = finding.sources[0];
  if (!sourceTool) return { ok: false, error: "finding has no recorded source tool — no original detection mechanism to reuse (§56)" };
  const fingerprint = finding.fingerprint ?? canonicalFindingFingerprint({
    host: finding.host ?? "", port: finding.port ?? undefined, endpoint: finding.endpoint ?? undefined,
    parameter: finding.parameter ?? undefined, vulnClass: finding.vulnClass ?? "UNKNOWN",
    cve: finding.cve ?? undefined, cwe: finding.cwe ?? undefined,
  });
  const rationale = [
    `targeted retest via original tool ${sourceTool}${finding.checkReference ? ` check ${finding.checkReference}` : ""} (§56)`,
    "execution re-passes authorization, scope, policy and budget gates (§57)",
  ];
  return {
    ok: true,
    plan: {
      sourceTool,
      ...(finding.checkReference ? { checkReference: finding.checkReference } : {}),
      canonicalFingerprint: fingerprint,
      target: {
        ...(finding.host ? { host: finding.host } : {}),
        ...(finding.port ? { port: finding.port } : {}),
        ...(finding.endpoint ? { endpoint: finding.endpoint } : {}),
      },
      rationale,
    },
  };
}

export type RetestOutcome = "RESOLVED" | "REOPENED";

/**
 * Judge a completed retest (§55/§99): the targeted check produced a set
 * of canonical fingerprints. The original issue among them → the
 * remediation failed → REOPENED. Absent → RESOLVED. A retest that
 * produced NO evidence at all (tool unavailable) must be judged by the
 * caller as FAILED, never as RESOLVED — absence of evidence is not
 * evidence of absence.
 */
export function judgeRetest(plan: RetestPlan, producedFingerprints: string[]): RetestOutcome {
  return producedFingerprints.includes(plan.canonicalFingerprint) ? "REOPENED" : "RESOLVED";
}
