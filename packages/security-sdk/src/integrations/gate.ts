import type { GateResult, PrGatePreset, SanitizedFindingView, ScannerFailureBehavior } from "./types";

/**
 * SecurityQualityGateEngine (Prompt 24 §36–§39, §20–§22). Pure and
 * deterministic. The gate judges ONLY the findings a change
 * INTRODUCED (diff-aware, §19) plus coverage and scanner health —
 * pre-existing repository risk stays visible in the repository view
 * but does not fail a PR gate unless a typed rule says so.
 *
 * Scanner failure handling is policy (§39): FAIL_CLOSED (default for
 * critical required checks), WARN, or FAIL_OPEN. A gate NEVER passes
 * silently when a required scanner produced no result under
 * FAIL_CLOSED.
 */

export type GateRule =
  | { kind: "maxNewCritical"; max: number }
  | { kind: "maxNewHigh"; max: number }
  | { kind: "blockNewKEV" }
  | { kind: "blockVerifiedCritical" }
  | { kind: "blockNewVerifiedSeverity"; severity: string }
  | { kind: "blockNewSecrets" }
  | { kind: "blockPolicyViolations" }
  | { kind: "minimumScanCoverage"; minimumPercent: number }
  | { kind: "requiredScanners"; scanners: string[] };

export interface GatePolicyView {
  rules: GateRule[];
  scannerFailureBehavior: ScannerFailureBehavior;
}

export interface GateScannerResult {
  scanner: string;
  status: "COMPLETED" | "FAILED" | "UNAVAILABLE" | "SKIPPED";
}

export interface GateEvaluationInput {
  /** Findings classified NEW against the baseline (§19/§40). */
  newFindings: Array<Pick<SanitizedFindingView, "severity" | "verificationStatus" | "kevListed" | "isSecretFinding"> & { policyViolation?: boolean }>;
  /** Scan coverage 0–100; null = unknown (cannot be proven). */
  coveragePercent: number | null;
  scannerResults: GateScannerResult[];
}

export interface GateRuleResult {
  rule: string;
  outcome: "PASS" | "FAIL" | "WARN";
  detail: string;
}

export interface GateEvaluation {
  result: GateResult;
  ruleResults: GateRuleResult[];
  summary: {
    newCritical: number; newHigh: number; newTotal: number;
    newKev: number; newSecrets: number; newVerifiedCritical: number;
    coveragePercent: number | null;
  };
}

const SEVERITY_RANK: Record<string, number> = { INFORMATIONAL: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export function evaluateGate(input: GateEvaluationInput, policy: GatePolicyView): GateEvaluation {
  const findings = input.newFindings;
  const summary = {
    newCritical: findings.filter((f) => f.severity === "CRITICAL").length,
    newHigh: findings.filter((f) => f.severity === "HIGH").length,
    newTotal: findings.length,
    newKev: findings.filter((f) => f.kevListed).length,
    newSecrets: findings.filter((f) => f.isSecretFinding).length,
    newVerifiedCritical: findings.filter((f) => f.severity === "CRITICAL" && f.verificationStatus === "CONFIRMED").length,
    coveragePercent: input.coveragePercent,
  };
  if (policy.rules.length === 0) {
    return { result: "SKIPPED", ruleResults: [], summary };
  }
  const ruleResults: GateRuleResult[] = [];
  for (const rule of policy.rules) {
    ruleResults.push(evaluateRule(rule, input, summary, policy.scannerFailureBehavior));
  }
  const result: GateResult = ruleResults.some((r) => r.outcome === "FAIL")
    ? "FAIL"
    : ruleResults.some((r) => r.outcome === "WARN")
      ? "WARN"
      : "PASS";
  return { result, ruleResults, summary };
}

function evaluateRule(
  rule: GateRule,
  input: GateEvaluationInput,
  summary: GateEvaluation["summary"],
  failureBehavior: ScannerFailureBehavior,
): GateRuleResult {
  const name = rule.kind;
  switch (rule.kind) {
    case "maxNewCritical":
      return summary.newCritical > rule.max
        ? { rule: name, outcome: "FAIL", detail: `${summary.newCritical} new critical finding(s) exceed max ${rule.max}` }
        : { rule: name, outcome: "PASS", detail: `${summary.newCritical} new critical finding(s) within max ${rule.max}` };
    case "maxNewHigh":
      return summary.newHigh > rule.max
        ? { rule: name, outcome: "FAIL", detail: `${summary.newHigh} new high finding(s) exceed max ${rule.max}` }
        : { rule: name, outcome: "PASS", detail: `${summary.newHigh} new high finding(s) within max ${rule.max}` };
    case "blockNewKEV":
      return summary.newKev > 0
        ? { rule: name, outcome: "FAIL", detail: `${summary.newKev} new KEV-listed finding(s)` }
        : { rule: name, outcome: "PASS", detail: "no new KEV-listed findings" };
    case "blockVerifiedCritical":
      return summary.newVerifiedCritical > 0
        ? { rule: name, outcome: "FAIL", detail: `${summary.newVerifiedCritical} new verified critical finding(s)` }
        : { rule: name, outcome: "PASS", detail: "no new verified critical findings" };
    case "blockNewVerifiedSeverity": {
      const threshold = SEVERITY_RANK[rule.severity] ?? 3;
      const count = input.newFindings.filter(
        (f) => f.verificationStatus === "CONFIRMED" && (SEVERITY_RANK[f.severity] ?? 0) >= threshold,
      ).length;
      return count > 0
        ? { rule: name, outcome: "FAIL", detail: `${count} new verified finding(s) at or above ${rule.severity}` }
        : { rule: name, outcome: "PASS", detail: `no new verified findings at or above ${rule.severity}` };
    }
    case "blockNewSecrets":
      return summary.newSecrets > 0
        ? { rule: name, outcome: "FAIL", detail: `${summary.newSecrets} new secret finding(s)` }
        : { rule: name, outcome: "PASS", detail: "no new secret findings" };
    case "blockPolicyViolations": {
      const count = input.newFindings.filter((f) => f.policyViolation).length;
      return count > 0
        ? { rule: name, outcome: "FAIL", detail: `${count} new policy violation(s)` }
        : { rule: name, outcome: "PASS", detail: "no new policy violations" };
    }
    case "minimumScanCoverage": {
      if (summary.coveragePercent === null) {
        // Coverage cannot be proven: under FAIL_CLOSED this breaches;
        // FAIL_OPEN tolerates it; WARN surfaces it (§39 semantics).
        if (failureBehavior === "FAIL_OPEN") return { rule: name, outcome: "PASS", detail: "coverage unknown — tolerated by FAIL_OPEN policy" };
        if (failureBehavior === "WARN") return { rule: name, outcome: "WARN", detail: "scan coverage unknown" };
        return { rule: name, outcome: "FAIL", detail: "scan coverage unknown — FAIL_CLOSED policy requires proven coverage" };
      }
      return summary.coveragePercent < rule.minimumPercent
        ? { rule: name, outcome: "FAIL", detail: `coverage ${summary.coveragePercent}% below minimum ${rule.minimumPercent}%` }
        : { rule: name, outcome: "PASS", detail: `coverage ${summary.coveragePercent}% meets minimum ${rule.minimumPercent}%` };
    }
    case "requiredScanners": {
      const missing = rule.scanners.filter((s) => {
        const r = input.scannerResults.find((x) => x.scanner === s);
        return !r || r.status === "FAILED" || r.status === "UNAVAILABLE";
      });
      if (missing.length === 0) return { rule: name, outcome: "PASS", detail: "all required scanners completed" };
      if (failureBehavior === "FAIL_OPEN") return { rule: name, outcome: "PASS", detail: `required scanner(s) unavailable (${missing.join(", ")}) — tolerated by FAIL_OPEN policy` };
      if (failureBehavior === "WARN") return { rule: name, outcome: "WARN", detail: `required scanner(s) unavailable: ${missing.join(", ")}` };
      return { rule: name, outcome: "FAIL", detail: `required scanner(s) unavailable under FAIL_CLOSED: ${missing.join(", ")} (§123)` };
    }
  }
}

/** §20: PR gate presets expand to typed rules (§38). */
export function prPresetToRules(preset: PrGatePreset): GateRule[] {
  switch (preset) {
    case "FAIL_ON_NEW_CRITICAL": return [{ kind: "maxNewCritical", max: 0 }];
    case "FAIL_ON_NEW_HIGH": return [{ kind: "maxNewCritical", max: 0 }, { kind: "maxNewHigh", max: 0 }];
    case "FAIL_ON_NEW_VERIFIED_HIGH": return [{ kind: "blockNewVerifiedSeverity", severity: "HIGH" }];
    case "FAIL_ON_NEW_KEV": return [{ kind: "blockNewKEV" }];
    case "FAIL_ON_NEW_SECRET": return [{ kind: "blockNewSecrets" }];
    case "FAIL_ON_POLICY_VIOLATION": return [{ kind: "blockPolicyViolations" }];
  }
}

/** Validate untrusted policy input into typed rules (§38). Unknown
 *  rule kinds are rejected — a gate policy is data, never code. */
export function parseGateRules(raw: unknown): { ok: boolean; rules: GateRule[]; errors: string[] } {
  if (!Array.isArray(raw)) return { ok: false, rules: [], errors: ["rules must be an array"] };
  const rules: GateRule[] = [];
  const errors: string[] = [];
  for (const entry of raw as Array<Record<string, unknown>>) {
    const kind = entry?.kind;
    switch (kind) {
      case "maxNewCritical":
      case "maxNewHigh":
        if (typeof entry.max !== "number" || entry.max < 0) errors.push(`${kind}.max must be a non-negative number`);
        else rules.push({ kind, max: entry.max });
        break;
      case "blockNewKEV": case "blockVerifiedCritical": case "blockNewSecrets": case "blockPolicyViolations":
        rules.push({ kind });
        break;
      case "blockNewVerifiedSeverity":
        if (typeof entry.severity !== "string" || !(entry.severity in SEVERITY_RANK)) errors.push("blockNewVerifiedSeverity.severity must be a known severity");
        else rules.push({ kind, severity: entry.severity });
        break;
      case "minimumScanCoverage":
        if (typeof entry.minimumPercent !== "number" || entry.minimumPercent < 0 || entry.minimumPercent > 100) errors.push("minimumScanCoverage.minimumPercent must be 0–100");
        else rules.push({ kind, minimumPercent: entry.minimumPercent });
        break;
      case "requiredScanners":
        if (!Array.isArray(entry.scanners) || entry.scanners.some((s) => typeof s !== "string")) errors.push("requiredScanners.scanners must be a string array");
        else rules.push({ kind, scanners: entry.scanners as string[] });
        break;
      default:
        errors.push(`unknown gate rule kind: ${String(kind)}`);
    }
  }
  return { ok: errors.length === 0, rules, errors };
}
