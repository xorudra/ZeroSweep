/**
 * Prompt 14 — targeted cloud retesting (§73).
 *
 * A retest re-checks the SPECIFIC resource and control of one cloud
 * finding through the same gated scan pipeline (a child scan) — never
 * an account-wide rescan by default, and never a state change: the
 * retest itself is read-only like every cloud assessment (§7).
 * Outcomes: the check now passes / configuration changed (RESOLVED),
 * the issue persists (CONFIRMED_OPEN), or evidence is inconclusive
 * (MANUAL_REVIEW_REQUIRED) — a failed retest stage is never reported
 * as resolved (Phase 11 discipline).
 */
import { CLOUD_RULE_CONTROLS } from "./analysis";
import type { CloudProvider } from "./types";

export interface CloudRetestPlan {
  /** Stage chain for the child scan: auth → targeted inventory → the
   *  one relevant analysis section → correlation/risk/compliance/tail. */
  stages: string[];
  /** The single analysis section to run for this rule. */
  analysisSection: "IAM_ANALYSIS" | "NETWORK_ANALYSIS" | "STORAGE_ANALYSIS" | "ENCRYPTION_ANALYSIS" | "LOGGING_ANALYSIS" | "CLOUD_CSPM";
  provider: CloudProvider;
  providerResourceId?: string;
  ruleId?: string;
  controlId?: string;
}

const RULE_SECTION: Record<string, CloudRetestPlan["analysisSection"]> = {
  "iam-admin-equivalent": "IAM_ANALYSIS",
  "iam-wildcard-actions": "IAM_ANALYSIS",
  "iam-broad-trust": "IAM_ANALYSIS",
  "mfa-not-enabled": "IAM_ANALYSIS",
  "iam-long-lived-credentials": "IAM_ANALYSIS",
  "iam-stale-privileged-access": "IAM_ANALYSIS",
  "storage-public-access": "STORAGE_ANALYSIS",
  "storage-encryption": "STORAGE_ANALYSIS",
  "storage-encryption-kms": "ENCRYPTION_ANALYSIS",
  "storage-logging": "LOGGING_ANALYSIS",
  "storage-versioning": "STORAGE_ANALYSIS",
  "database-public-access": "NETWORK_ANALYSIS",
  "database-encryption": "ENCRYPTION_ANALYSIS",
  "database-backup": "STORAGE_ANALYSIS",
  "database-tls": "NETWORK_ANALYSIS",
  "firewall-sensitive-port-world": "NETWORK_ANALYSIS",
  "firewall-world-open-port": "NETWORK_ANALYSIS",
  "serverless-public-access": "NETWORK_ANALYSIS",
  "audit-logging-disabled": "LOGGING_ANALYSIS",
  "audit-logging-single-region": "LOGGING_ANALYSIS",
  "security-service-disabled": "LOGGING_ANALYSIS",
  "kms-rotation-disabled": "ENCRYPTION_ANALYSIS",
};

export function planCloudRetest(finding: {
  cloudProvider?: string | null;
  providerResourceId?: string | null;
  ruleId?: string | null;
}): CloudRetestPlan | null {
  const provider = finding.cloudProvider;
  if (provider !== "AWS" && provider !== "AZURE" && provider !== "GCP") return null;
  const ruleId = finding.ruleId ?? undefined;
  const section = (ruleId ? RULE_SECTION[ruleId] : undefined) ?? "CLOUD_CSPM";
  const controlId = ruleId ? CLOUD_RULE_CONTROLS[ruleId]?.[provider]?.controlId : undefined;
  return {
    stages: [
      "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "CLOUD_AUTH", "CLOUD_INVENTORY",
      section, "CORRELATION", "RISK_ANALYSIS", "CLOUD_COMPLIANCE", "QUALITY_GATE", "REPORT_GENERATION",
    ],
    analysisSection: section,
    provider,
    ...(finding.providerResourceId ? { providerResourceId: finding.providerResourceId } : {}),
    ...(ruleId ? { ruleId } : {}),
    ...(controlId ? { controlId } : {}),
  };
}
