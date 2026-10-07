/**
 * Prompt 14 — cloud fingerprints, cross-tool / IaC-live correlation,
 * risk paths, quality gate and remediation guidance (§60–§72).
 *
 * Correlation is deterministic identity math: Prowler + ScoutSuite +
 * the provider-native analyzer reporting the same public bucket yield
 * ONE canonical finding with multiple observations (§60). IaC and
 * live observations of the same deployed resource correlate the same
 * way, preserving SOURCE and LIVE_CLOUD observations (§62). Risk
 * paths are defensive models over evidence-backed graph edges — they
 * are never executed (§66).
 */
import { createHash } from "node:crypto";
import type { NormalizedCloudRelationship, NormalizedCloudResource, NormalizedCloudRiskPath, NormalizedFinding } from "../findings/finding.types";

function hash(parts: string[]): string {
  return createHash("sha256").update(parts.map((p) => p.trim().toLowerCase()).join("|")).digest("hex");
}

/** The cloud fingerprint (§61): provider + account + region +
 *  provider resource id + control/rule + finding class. Two tools
 *  reporting the same issue on the same resource produce the same key. */
export function cloudFingerprint(input: {
  provider: string; accountRef: string; region?: string;
  providerResourceId: string; ruleId: string; findingClass: string;
}): string {
  return `cloud:${hash([input.provider, input.accountRef, input.region ?? "", input.providerResourceId, input.ruleId, input.findingClass])}`;
}

/** Checkov rule → live cloud check correlation catalog (§62/§33): a
 *  static IaC observation and a live inventory observation describe
 *  the SAME issue when the Checkov rule maps to the live rule AND the
 *  Terraform/ARM resource identity maps to the deployed resource id.
 *  Mapping is explicit and conservative — unmapped rules never merge. */
export const IAC_RULE_TO_LIVE_RULE: Record<string, string> = {
  CKV_AWS_20: "storage-public-access", // S3 ACL public read
  CKV_AWS_53: "storage-public-access", // S3 block public access missing
  CKV_AWS_54: "storage-public-access",
  CKV_AWS_55: "storage-public-access",
  CKV_AWS_56: "storage-public-access",
  CKV_AWS_24: "firewall-sensitive-port-world", // SG ingress 0.0.0.0/0 to port 22
  CKV_AWS_25: "firewall-sensitive-port-world", // SG ingress 0.0.0.0/0 to port 3389
  CKV_AWS_23: "firewall-rule-undocumented",
  CKV_AWS_277: "firewall-sensitive-port-world",
  CKV_AWS_16: "database-encryption", // RDS encryption
  CKV_AWS_17: "database-public-access", // RDS publicly accessible
  CKV_AWS_18: "storage-logging", // S3 access logging
  CKV_AWS_21: "storage-versioning", // S3 versioning
  CKV_AWS_145: "storage-encryption-kms",
  CKV2_AWS_6: "storage-public-access",
  CKV_AZURE_190: "storage-public-access",
  CKV_GCP_62: "storage-logging",
  CKV_GCP_29: "storage-public-access",
};

/** Terraform/CloudFormation resource address → provider resource id
 *  candidates (§62): identity mapping is reliable only when the IaC
 *  resource NAME matches the deployed resource's name within the same
 *  account. Returns the match key or null (UNMAPPED — never guessed). */
export function iacLiveMatchKey(input: { ruleId?: string; resourceName?: string }): string | null {
  if (!input.ruleId || !input.resourceName) return null;
  const liveRule = IAC_RULE_TO_LIVE_RULE[input.ruleId];
  if (!liveRule) return null;
  return `${liveRule}:${input.resourceName.trim().toLowerCase()}`;
}

export function liveMatchKey(input: { ruleId?: string; resourceName?: string }): string | null {
  if (!input.ruleId || !input.resourceName) return null;
  return `${input.ruleId}:${input.resourceName.trim().toLowerCase()}`;
}

/** Drift states for IaC-vs-live comparison (§63). */
export type IacDriftState = "MATCHED" | "DRIFTED" | "UNMAPPED" | "UNKNOWN";

export function classifyIacDrift(input: {
  iacValue?: string; liveValue?: string; mapped: boolean;
}): IacDriftState {
  if (!input.mapped) return "UNMAPPED";
  if (input.iacValue === undefined || input.liveValue === undefined) return "UNKNOWN";
  return input.iacValue === input.liveValue ? "MATCHED" : "DRIFTED";
}

/** Build defensive risk paths (§66) from evidence-backed edges:
 *  PUBLIC resource → workload → assumed identity → sensitive
 *  resource. Confidence (§67) scales with how many edges are backed
 *  by provider evidence; a path is a model, never a compromise claim. */
export function buildCloudRiskPaths(input: {
  resources: NormalizedCloudResource[];
  relationships: NormalizedCloudRelationship[];
  findings: NormalizedFinding[];
}): NormalizedCloudRiskPath[] {
  const paths: NormalizedCloudRiskPath[] = [];
  const assumes = input.relationships.filter((r) => r.relationship === "ASSUMES");
  const sensitive = input.resources.filter((r) =>
    r.resourceType.includes("S3") || r.resourceType.includes("STORAGE") || r.resourceType.includes("RDS")
    || r.resourceType.includes("SQL") || r.resourceType.includes("SECRETS"));
  for (const resource of input.resources) {
    if (resource.exposure !== "PUBLIC") continue;
    const edge = assumes.find((a) => a.fromRef === resource.providerResourceId);
    if (!edge) continue;
    const relatedFindings = input.findings.filter((f) => f.providerResourceId === resource.providerResourceId);
    const steps: NormalizedCloudRiskPath["steps"] = [
      { kind: "ENDPOINT", ref: resource.providerResourceId, label: `Public ${resource.resourceType} ${resource.name}` },
      { kind: "WORKLOAD", ref: resource.providerResourceId, label: resource.name },
      { kind: "IDENTITY", ref: edge.toRef, label: edge.toRef },
    ];
    if (sensitive.length > 0 && sensitive[0]!.providerResourceId !== resource.providerResourceId) {
      steps.push({ kind: "RESOURCE", ref: sensitive[0]!.providerResourceId, label: `Sensitive resource ${sensitive[0]!.name}` });
    }
    paths.push({
      title: `Public exposure path: ${resource.name} → identity ${edge.toRef}`,
      steps,
      confidence: steps.length >= 4 ? "HIGH" : "MEDIUM",
      findingFingerprints: relatedFindings.map((f) => f.sourceFingerprint),
    });
  }
  return paths.slice(0, 100);
}

/** Cloud quality gate (§70): configurable deterministic policies over
 *  the scan's canonical findings + posture facts. Verdicts are PASSED
 *  / FAILED / WARNING — a failed gate is a recorded result, never a
 *  pipeline crash, and never modifies a cloud resource (§71). */
export interface CloudGatePolicy {
  version: string;
  denyPublicCriticalStorage: boolean;
  denyCriticalFindings: boolean;
  denyKevOnPublicWorkloads: boolean;
  denyUnrestrictedSensitivePorts: boolean;
  requireAuditLogging: boolean;
}

export const DEFAULT_CLOUD_GATE_POLICY: CloudGatePolicy = {
  version: "cloud-gate-v1",
  denyPublicCriticalStorage: true,
  denyCriticalFindings: true,
  denyKevOnPublicWorkloads: true,
  denyUnrestrictedSensitivePorts: true,
  requireAuditLogging: true,
};

export interface CloudGateInput {
  findings: { severity: string; findingClass?: string; exposureClass?: string; resourceType?: string; kevListed?: boolean }[];
  auditLoggingEnabled: boolean | null; // null = not observed → WARNING, not a silent pass
}

export function evaluateCloudSecurityGate(
  input: CloudGateInput, policy: CloudGatePolicy = DEFAULT_CLOUD_GATE_POLICY,
): { status: "PASSED" | "FAILED" | "WARNING"; failedRules: string[]; warningRules: string[] } {
  const failed: string[] = [];
  const warnings: string[] = [];
  if (policy.denyPublicCriticalStorage && input.findings.some((f) => f.findingClass === "PUBLIC_EXPOSURE" && (f.resourceType?.includes("S3") || f.resourceType?.includes("STORAGE")) && (f.severity === "CRITICAL" || f.severity === "HIGH"))) {
    failed.push("NO_PUBLIC_CRITICAL_STORAGE");
  }
  if (policy.denyCriticalFindings && input.findings.some((f) => f.severity === "CRITICAL")) failed.push("NO_CRITICAL_CLOUD_FINDINGS");
  if (policy.denyKevOnPublicWorkloads && input.findings.some((f) => f.kevListed && f.exposureClass === "PUBLIC")) failed.push("NO_KEV_ON_PUBLIC_WORKLOADS");
  const NETWORK_CONTROL_TYPES = ["SECURITY_GROUP", "NSG", "FIREWALL"];
  if (policy.denyUnrestrictedSensitivePorts && input.findings.some((f) => f.findingClass === "PUBLIC_EXPOSURE" && NETWORK_CONTROL_TYPES.some((t) => f.resourceType?.includes(t)))) {
    failed.push("NO_UNRESTRICTED_SENSITIVE_MANAGEMENT_PORTS");
  }
  if (policy.requireAuditLogging) {
    if (input.auditLoggingEnabled === false) failed.push("AUDIT_LOGGING_REQUIRED");
    else if (input.auditLoggingEnabled === null) warnings.push("AUDIT_LOGGING_NOT_OBSERVED");
  }
  return { status: failed.length > 0 ? "FAILED" : warnings.length > 0 ? "WARNING" : "PASSED", failedRules: failed, warningRules: warnings };
}

/** Deterministic remediation guidance (§71/§72): provider + tool +
 *  curated-policy guidance text and a SUGGESTED code snippet. The
 *  platform never applies these — generated changes are review-only. */
export function cloudRemediationGuidance(input: { ruleId: string; provider: string }): { guidance: string; snippet?: { language: string; code: string } } {
  const table: Record<string, { guidance: string; snippet?: { language: string; code: string } }> = {
    "storage-public-access": {
      guidance: "Restrict the storage resource: enable the provider public-access block and remove public ACL/policy grants (§71).",
      snippet: { language: "terraform", code: "# review-only suggestion (§72) — never auto-applied\nresource \"aws_s3_bucket_public_access_block\" \"this\" {\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}" },
    },
    "firewall-sensitive-port-world": {
      guidance: "Restrict the firewall/security-group rule: scope the source range to the approved management network and document the rule (§71).",
    },
    "database-public-access": { guidance: "Remove public accessibility from the managed database and place it in private subnets with security-group-only access (§71)." },
    "database-encryption": { guidance: "Enable encryption at rest with a customer-managed KMS key where the provider requires it (§71)." },
    "storage-encryption-kms": { guidance: "Configure default encryption with a KMS key for the storage resource (§71)." },
    "storage-logging": { guidance: "Enable access/audit logging for the storage resource to a governed log destination (§71)." },
    "audit-logging-disabled": { guidance: "Enable the provider audit trail (CloudTrail / Activity Log / Cloud Audit Logs) in all regions with log validation (§71)." },
    "iam-admin-equivalent": { guidance: "Reduce IAM privilege: replace the administrator-equivalent grant with a scoped policy covering only the permissions the identity uses (§71)." },
    "iam-wildcard-actions": { guidance: "Reduce IAM privilege: enumerate the specific actions and resources instead of wildcard grants (§71)." },
    "mfa-not-enabled": { guidance: "Require MFA for the human identity — enforce it with a condition/policy, do not just enroll (§71)." },
  };
  return table[input.ruleId] ?? { guidance: "Remediate per the provider and tool guidance recorded on the finding; changes are reviewed and applied outside DSRclone (§71)." };
}
