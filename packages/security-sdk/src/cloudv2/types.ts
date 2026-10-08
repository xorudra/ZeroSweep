/**
 * Prompt 34 — Advanced Cloud, Container & Kubernetes Security V2:
 * shared types.
 *
 * V2 deepens Prompts 13/14 on the SAME canonical models — CloudAccount,
 * CloudResource, CloudIdentity, CloudRelationship, CloudRiskPath,
 * CloudDriftEvent, ContainerImage (+ the Prompt 12/30 SBOM subsystem),
 * KubernetesCluster, KubernetesWorkload, RuntimeSecurityEvent. The
 * types here describe the V2 orchestration layer only: connection
 * tests (§12), resource snapshots (§17), baselines (§97–§99), coverage
 * (§111–§115) and the three orchestrator pipelines (§103–§105).
 *
 * Nothing in this module can hold a credential value, a kubeconfig or
 * a secret: accounts and clusters carry secret REFERENCE names only
 * (§10/§72), snapshots carry bounded sanitized configuration (§17),
 * and Kubernetes inventory carries Secret METADATA only (§83).
 */
import type { CloudProvider } from "../cloudsec/types";

export type { CloudProvider };

/** §7: cloud environments. TEST and SANDBOX complete the Prompt 14
 *  set; CI remains valid for build estates. */
export const CLOUD_V2_ENVIRONMENTS = [
  "PRODUCTION", "STAGING", "DEVELOPMENT", "TEST", "SANDBOX", "CI", "UNKNOWN",
] as const;
export type CloudV2Environment = (typeof CLOUD_V2_ENVIRONMENTS)[number];

/** §12: governed connection-test outcomes. */
export const CLOUD_CONNECTION_RESULTS = [
  "CONNECTED", "CONNECTED_WITH_LIMITATIONS", "AUTH_FAILED",
  "PERMISSION_LIMITED", "EXPIRED", "UNREACHABLE",
] as const;
export type CloudConnectionResult = (typeof CLOUD_CONNECTION_RESULTS)[number];

/**
 * Facts a connection test is evaluated from (§12/§13). These come from
 * the provider transport: in this build the live transports are
 * deliberately unwired (NOT_CONFIGURED), so production facts report
 * `transportConfigured: false` and the honest verdict is UNREACHABLE —
 * never a fabricated CONNECTED. Fixture transports supply facts in
 * tests only.
 */
export interface CloudConnectionProbeFacts {
  credentialReferencePresent: boolean;
  /** The secret store could resolve the reference (existence only). */
  secretResolvable?: boolean;
  /** A provider transport is wired for this provider at all. */
  transportConfigured: boolean;
  /** Provider reachability as observed by the transport. */
  reachable?: boolean;
  /** Outcome of the read-only identity call, when one was possible. */
  authOutcome?: "OK" | "AUTH_FAILED" | "EXPIRED";
  /** Account identity the credential actually belongs to (§145). */
  identityAccountId?: string;
  /** Account identity the platform account is registered under. */
  expectedAccountId?: string;
  /** Read permissions the probe found missing (§13) — names only. */
  missingPermissions?: string[];
  /** Missing permissions that block core inventory/IAM collection. */
  coreMissingPermissions?: string[];
}

export interface CloudConnectionEvaluation {
  result: CloudConnectionResult;
  accountMatch: boolean;
  limitations: Array<{ code: string; detail: string }>;
  missingPermissions: string[];
}

/** §115: the closed set of skipped/coverage-gap reasons. */
export const CLOUD_V2_SKIPPED_REASONS = [
  "NOT_AUTHORIZED", "MISSING_PERMISSION", "TOOL_UNAVAILABLE",
  "RATE_LIMITED", "UNSUPPORTED", "SECRET_UNAVAILABLE", "POLICY_BLOCKED",
] as const;
export type CloudV2SkippedReason = (typeof CLOUD_V2_SKIPPED_REASONS)[number];

export interface CloudV2CoverageGap {
  area: string;
  reason: CloudV2SkippedReason;
  detail: string;
}

/** §110: an assessment with any gap is COMPLETED_WITH_GAPS — a missing
 *  permission is never a clean result (§166). */
export function completionForGaps(gaps: CloudV2CoverageGap[]): "COMPLETED" | "COMPLETED_WITH_GAPS" {
  return gaps.length > 0 ? "COMPLETED_WITH_GAPS" : "COMPLETED";
}

export interface CloudV2PipelineStage {
  stage: string;
  status: "PENDING" | "COMPLETED" | "COMPLETED_WITH_GAPS" | "SKIPPED" | "BLOCKED" | "FAILED";
  detail: string;
}

/** §103: Cloud Security Orchestrator pipeline. */
export const CLOUD_PIPELINE_STAGES = [
  "CONNECT", "INVENTORY", "POSTURE", "IAM", "EXPOSURE", "VULNERABILITY",
  "COMPLIANCE", "CORRELATION", "RISK", "REMEDIATION", "REPORT",
] as const;

/** §104: Container Orchestrator pipeline. */
export const CONTAINER_PIPELINE_STAGES = [
  "IMAGE_DISCOVERY", "SBOM", "VULNERABILITY", "CONFIGURATION",
  "DEPLOYMENT_CORRELATION", "RISK", "REMEDIATION",
] as const;

/** §105: Kubernetes Orchestrator pipeline. */
export const KUBERNETES_PIPELINE_STAGES = [
  "CONNECT", "INVENTORY", "RBAC", "WORKLOAD_CONFIGURATION", "BENCHMARK",
  "IMAGE_CORRELATION", "EXPOSURE", "RUNTIME_SIGNALS", "RISK", "REMEDIATION",
] as const;

/** §97–§99: one declarative baseline rule. Expectations are posture
 *  facts the platform can observe — never provider mutations (§124). */
export interface CloudV2BaselineRule {
  ruleId: string;
  expectation: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
}

export interface CloudV2BaselineDeviation {
  ruleId: string;
  expectation: string;
  observed: string;
  severity: CloudV2BaselineRule["severity"];
}

/** §132: attack-path steps are labelled by evidence strength in the UI. */
export type CloudV2EvidenceLabel = "OBSERVED" | "INFERRED";

export interface CloudV2AttackPathStep {
  kind: string;
  ref: string;
  label: string;
  evidence: CloudV2EvidenceLabel;
}

export interface CloudV2AttackPathCandidate {
  title: string;
  domain: "CLOUD" | "KUBERNETES";
  steps: CloudV2AttackPathStep[];
  confidence: "LOW" | "MEDIUM" | "HIGH";
  /** §33/§90: a candidate is analytical — it is never executed. */
  executed: false;
}
