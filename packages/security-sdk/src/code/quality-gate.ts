import type {
  QualityGateEvaluation, QualityGatePolicy, QualityGateSummary,
} from "./types";

/**
 * Security quality gate evaluation (Prompt 12 §81/§82, §104). Pure and
 * deterministic: the same summary + policy always yields the same
 * verdict. A FAILED gate is a scan RESULT recorded on the scan — the
 * stage itself completes and reports the evaluation.
 */
export function evaluateQualityGate(summary: QualityGateSummary, policy: QualityGatePolicy): QualityGateEvaluation {
  const failedRules: string[] = [];
  const warningRules: string[] = [];
  for (const rule of policy.rules) {
    let breached = false;
    if (rule.kind === "MAX_SEVERITY_COUNT") {
      breached = (summary.bySeverity[rule.severity ?? ""] ?? 0) > rule.maxAllowed;
    } else if (rule.kind === "SECRET_PRESENT") {
      breached = summary.secrets > rule.maxAllowed;
    } else if (rule.kind === "NEW_FINDINGS_OF_SEVERITY") {
      breached = (summary.newBySeverity[rule.severity ?? ""] ?? 0) > rule.maxAllowed;
    } else if (rule.kind === "DEPENDENCY_VULNERABILITY") {
      breached = summary.dependencyVulnerabilities > rule.maxAllowed && (rule.severity === undefined || (summary.bySeverity[rule.severity] ?? 0) > 0);
    }
    if (breached) {
      if (rule.onBreach === "FAIL") failedRules.push(rule.id);
      else warningRules.push(rule.id);
    }
  }
  return {
    status: failedRules.length > 0 ? "FAILED" : warningRules.length > 0 ? "WARNING" : "PASSED",
    failedRules,
    warningRules,
    evaluatedRules: policy.rules.length,
    summary,
  };
}

/** Build the gate summary from correlated findings (§81 inputs). */
export function summarizeForQualityGate(findings: {
  severity: string;
  secret?: unknown;
  componentPurl?: string;
  baselineStatus?: string;
}[]): QualityGateSummary {
  const bySeverity: Record<string, number> = {};
  const newBySeverity: Record<string, number> = {};
  let secrets = 0;
  let dependencyVulnerabilities = 0;
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    if (f.baselineStatus === "NEW") newBySeverity[f.severity] = (newBySeverity[f.severity] ?? 0) + 1;
    if (f.secret) secrets += 1;
    if (f.componentPurl) dependencyVulnerabilities += 1;
  }
  return { bySeverity, newBySeverity, secrets, dependencyVulnerabilities, totalFindings: findings.length };
}
