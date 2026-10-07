import type { Severity } from "@dsrclone/types";

/**
 * Unified vulnerability-management vocabulary (Prompt 20 §5–§11).
 *
 * Every engine built in Prompts 5–19 already lands on the same Finding /
 * FindingObservation records; this module is the SHARED language the
 * unified layer speaks about them. Nothing here flattens domain
 * identity: the source domain (§5) and category (§6) are preserved on
 * every canonical finding, severity stays what the scanner measured
 * (§10), priority stays a separate business decision (§11), and
 * verification stays independent of both (§9).
 */

export const FINDING_SOURCES = [
  "WEB", "NETWORK", "API", "RECON", "SAST", "SCA", "SECRET", "CONTAINER",
  "KUBERNETES", "CLOUD", "IDENTITY", "MOBILE", "BINARY", "WIRELESS",
  "MANUAL", "EXTERNAL_IMPORT",
] as const;
export type UnifiedFindingSource = (typeof FINDING_SOURCES)[number];

export const FINDING_CATEGORIES = [
  "VULNERABILITY", "MISCONFIGURATION", "SECRET", "IAM_RISK",
  "PUBLIC_EXPOSURE", "COMPLIANCE_FAILURE", "CODE_FINDING",
  "DEPENDENCY_VULNERABILITY", "RUNTIME_EVENT", "WIRELESS_FINDING",
  "BINARY_FINDING", "MOBILE_FINDING",
] as const;
export type FindingCategory = (typeof FINDING_CATEGORIES)[number];

/** §8 standardized workflow lifecycle (extends the Prompt 11 machine). */
export const UNIFIED_LIFECYCLE_STATUSES = [
  "NEW", "TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED",
  "RETEST_PENDING", "RESOLVED", "REOPENED", "ACCEPTED_RISK",
  "FALSE_POSITIVE", "DUPLICATE", "MITIGATED",
] as const;
export type UnifiedLifecycleStatus = (typeof UNIFIED_LIFECYCLE_STATUSES)[number];

/** §9 verification — independent of workflow status and of severity. */
export const UNIFIED_VERIFICATION_STATUSES = ["UNVERIFIED", "LIKELY", "VERIFIED", "INCONCLUSIVE"] as const;
export type UnifiedVerificationStatus = (typeof UNIFIED_VERIFICATION_STATUSES)[number];

/**
 * The stored FindingVerificationStatus predates the unified vocabulary
 * (CONFIRMED ≈ a deterministic/human verification, REJECTED = review
 * rejected the finding). The mapping is explicit and lossy-by-design:
 * reports and dashboards always speak the unified vocabulary.
 */
export function toUnifiedVerification(stored: string | null | undefined): UnifiedVerificationStatus {
  switch (stored) {
    case "CONFIRMED": return "VERIFIED";
    case "LIKELY": return "LIKELY";
    case "INCONCLUSIVE": return "INCONCLUSIVE";
    default: return "UNVERIFIED"; // UNVERIFIED, REJECTED (rejection lives in lifecycle/review, not verification)
  }
}

/** §10: severities are standardized; the scanner's original is preserved
 *  separately on every observation (rawSeverity). INFO ≡ INFORMATIONAL. */
export function normalizeSeverity(raw: string | null | undefined): Severity {
  switch ((raw ?? "").trim().toUpperCase()) {
    case "CRITICAL": return "CRITICAL";
    case "HIGH": return "HIGH";
    case "MEDIUM": case "MODERATE": return "MEDIUM";
    case "LOW": return "LOW";
    default: return "INFORMATIONAL"; // INFO, NONE, unknown — never upgraded on a guess
  }
}

/** The canonical finding as the unified layer sees it (§7). A structural
 *  view over the stored Finding row + its unified extension fields. */
export interface CanonicalFindingView {
  id: string;
  workspaceId: string;
  title: string;
  description: string;
  sourceDomain?: string | null;
  category?: string | null;
  severity: Severity;
  priority?: string | null; // P0..P4 — separate from severity (§11)
  confidence: number;
  verificationStatus: string;
  lifecycleStatus: string;
  cve?: string | null;
  cwe?: string | null;
  cpe?: string | null;
  cvssScore?: number | null;
  epssScore?: number | null;
  kevListed?: boolean;
  assetId?: string | null;
  host?: string | null;
  endpoint?: string | null;
  riskScore?: number | null;
  riskBand?: string | null;
  assignedToId?: string | null;
  assignedToTeam?: string | null;
  dueAt?: Date | string | null;
  firstSeen: Date | string;
  lastSeen?: Date | string;
  resolvedAt?: Date | string | null;
  reopenedAt?: Date | string | null;
  recurrenceCount?: number;
  isMock?: boolean;
  tags?: string[];
  environment?: string | null;
  dataSensitivity?: string | null;
}

/** §4: the complete observation contract. */
export interface UnifiedObservation {
  id?: string;
  findingId: string;
  workspaceId: string;
  tool: string;
  toolVersion?: string | null;
  scannerInstance?: string | null;
  scanId?: string | null;
  targetRef?: string | null;
  assetId?: string | null;
  observedAt: Date | string;
  rawSeverity?: string | null;
  normalizedSeverity: Severity;
  ruleId?: string | null;
  location?: string | null;
  evidenceRef?: string | null;
  confidence?: number | null;
  verificationState?: string | null;
  rawArtifactRef?: string | null;
  sourceFingerprint: string;
}
