/**
 * Source Code Security Engine — shared types (Prompt 12).
 *
 * Repository content is HOSTILE INPUT (§2): it is acquired into isolated
 * snapshots, never executed (§14), and analyzed read-only. Secrets found
 * in code are represented ONLY as metadata (§40) — no type in this module
 * can carry a raw secret value.
 */

export const SOURCE_KINDS = ["GIT_REPOSITORY", "UPLOADED_ARCHIVE", "LOCAL_SOURCE_SNAPSHOT"] as const;
export type SourceKind = (typeof SOURCE_KINDS)[number];

/** Source analysis profiles (Prompt 12 §18). */
export const SOURCE_PROFILES = [
  "SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SAST_ONLY",
] as const;
export type SourceProfile = (typeof SOURCE_PROFILES)[number];

/** One file in a snapshot listing (§5). Paths are repository-relative. */
export interface SourceFileEntry {
  path: string;
  sizeBytes: number;
}

/** Immutable snapshot descriptor (§5): created at acquisition, never
 *  modified in place — a new commit or upload is a NEW snapshot. */
export interface SourceSnapshotDescriptor {
  repositoryId: string;
  commitSha?: string;
  branch?: string;
  snapshotHash: string;
  sourceKind: SourceKind;
  fileCount: number;
  totalSizeBytes: number;
  files: SourceFileEntry[];
}

/**
 * Repository execution policy (§14). The default — and the only mode the
 * automated pipeline uses — is DO_NOT_EXECUTE_SOURCE: source code is
 * READ, never RUN. No build scripts, package lifecycle hooks, git hooks,
 * generated build steps or target tests ever execute.
 */
export interface RepositoryExecutionPolicy {
  mode: "DO_NOT_EXECUTE_SOURCE";
  executeBuildScripts: false;
  executePackageScripts: false;
  executeTests: false;
  executeGitHooks: false;
  networkAccess: "NETWORK_DISABLED";
}

export const DEFAULT_REPOSITORY_EXECUTION_POLICY: RepositoryExecutionPolicy = {
  mode: "DO_NOT_EXECUTE_SOURCE",
  executeBuildScripts: false,
  executePackageScripts: false,
  executeTests: false,
  executeGitHooks: false,
  networkAccess: "NETWORK_DISABLED",
};

export type RepositoryAction =
  | "READ_ONLY_ANALYSIS"
  | "BUILD_SCRIPT"
  | "PACKAGE_LIFECYCLE_SCRIPT"
  | "TARGET_TEST"
  | "GIT_HOOK"
  | "SHELL_COMMAND";

/** §14/§108: anything beyond read-only analysis is a policy violation. */
export function executionPolicyViolation(
  policy: RepositoryExecutionPolicy,
  action: RepositoryAction,
): string | null {
  if (action === "READ_ONLY_ANALYSIS") return null;
  return `repository execution policy ${policy.mode} forbids ${action} — analyzed source is never executed (§14)`;
}

/** Source scan budget (§83) — every source scan is bounded. */
export interface SourceScanBudget {
  maxRepositorySizeMb: number;
  maxFiles: number;
  maxFileSizeMb: number;
  maxArchiveSizeMb: number;
  maxHistoryDepth: number;
  maxScanDurationSeconds: number;
  maxSastFindings: number;
  maxSecretFindings: number;
  maxDependencies: number;
  maxSbomSizeMb: number;
}

export const DEFAULT_SOURCE_BUDGET: SourceScanBudget = {
  maxRepositorySizeMb: 512,
  maxFiles: 50000,
  maxFileSizeMb: 25,
  maxArchiveSizeMb: 256,
  maxHistoryDepth: 100,
  maxScanDurationSeconds: 3600,
  maxSastFindings: 10000,
  maxSecretFindings: 5000,
  maxDependencies: 20000,
  maxSbomSizeMb: 25,
};

export const ADMIN_SOURCE_CAPS: SourceScanBudget = {
  maxRepositorySizeMb: 4096,
  maxFiles: 250000,
  maxFileSizeMb: 100,
  maxArchiveSizeMb: 1024,
  maxHistoryDepth: 1000,
  maxScanDurationSeconds: 14400,
  maxSastFindings: 100000,
  maxSecretFindings: 50000,
  maxDependencies: 100000,
  maxSbomSizeMb: 100,
};

/** Clamp a requested source budget into [1, admin cap] (§83). */
export function clampSourceBudget(requested: Partial<SourceScanBudget> = {}): SourceScanBudget {
  const out = {} as SourceScanBudget;
  for (const key of Object.keys(DEFAULT_SOURCE_BUDGET) as (keyof SourceScanBudget)[]) {
    const want = requested[key];
    const value = typeof want === "number" && Number.isFinite(want) ? want : DEFAULT_SOURCE_BUDGET[key];
    out[key] = Math.max(1, Math.min(Math.floor(value), ADMIN_SOURCE_CAPS[key]));
  }
  return out;
}

/** Secret types (§42) — classification only, never values. */
export const SECRET_TYPES = [
  "API_KEY", "TOKEN", "PRIVATE_KEY", "PASSWORD", "DATABASE_CREDENTIAL",
  "CLOUD_CREDENTIAL", "CERTIFICATE_SECRET", "GENERIC_SECRET",
] as const;
export type SecretType = (typeof SECRET_TYPES)[number];

/** Secret lifecycle (§44). Rotation is a workflow state — the platform
 *  never rotates (or validates against live services) on its own. */
export const SECRET_LIFECYCLE_STATUSES = [
  "OPEN", "ROTATION_REQUIRED", "ROTATED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED",
] as const;
export type SecretLifecycleStatus = (typeof SECRET_LIFECYCLE_STATUSES)[number];

/** File classification (§84/§87/§88). Generated and vendored code is
 *  still analyzed where practical, but classified honestly. */
export type RepositoryFileClass =
  | "SOURCE" | "TEST" | "GENERATED" | "VENDORED" | "CONFIGURATION"
  | "DOCUMENTATION" | "BINARY" | "BUILD_OUTPUT" | "DEPENDENCY_MANIFEST" | "UNKNOWN";

export interface DetectedLanguage {
  language: string;
  fileCount: number;
  /** Share of classified source files, 0..1. */
  percentage: number;
}

export interface LanguageDetectionResult {
  languages: DetectedLanguage[];
  primaryLanguage?: string;
  frameworks: string[];
  buildSystems: string[];
}

/** Quality gate (§81/§82): configurable rules over the scan summary; a
 *  FAILED gate is a scan RESULT, not a stage crash. */
export type QualityGateStatus = "PASSED" | "FAILED" | "WARNING" | "NOT_EVALUATED";

export interface QualityGateRule {
  id: string;
  kind: "MAX_SEVERITY_COUNT" | "SECRET_PRESENT" | "NEW_FINDINGS_OF_SEVERITY" | "DEPENDENCY_VULNERABILITY";
  severity?: string;
  maxAllowed: number;
  onBreach: "FAIL" | "WARN";
  description: string;
}

export interface QualityGatePolicy {
  version: string;
  rules: QualityGateRule[];
}

export interface QualityGateSummary {
  bySeverity: Record<string, number>;
  newBySeverity: Record<string, number>;
  secrets: number;
  dependencyVulnerabilities: number;
  totalFindings: number;
}

export interface QualityGateEvaluation {
  status: Exclude<QualityGateStatus, "NOT_EVALUATED">;
  failedRules: string[];
  warningRules: string[];
  evaluatedRules: number;
  summary: QualityGateSummary;
}

/** Default gate policy (§82): any CRITICAL or any detected secret fails;
 *  new HIGH findings warn. Tenants may configure stricter policies. */
export const DEFAULT_QUALITY_GATE_POLICY: QualityGatePolicy = {
  version: "1.0.0",
  rules: [
    { id: "no-critical", kind: "MAX_SEVERITY_COUNT", severity: "CRITICAL", maxAllowed: 0, onBreach: "FAIL", description: "No CRITICAL findings" },
    { id: "no-secrets", kind: "SECRET_PRESENT", maxAllowed: 0, onBreach: "FAIL", description: "No detected secrets (metadata-verified findings)" },
    { id: "no-new-high", kind: "NEW_FINDINGS_OF_SEVERITY", severity: "HIGH", maxAllowed: 0, onBreach: "WARN", description: "No NEW HIGH findings vs the previous snapshot baseline" },
    { id: "no-critical-dependencies", kind: "DEPENDENCY_VULNERABILITY", severity: "CRITICAL", maxAllowed: 0, onBreach: "FAIL", description: "No CRITICAL dependency vulnerabilities" },
  ],
};

/** Source exclusion policy (§85/§86): exclusions are explicit, reasoned
 *  and audited — never silent suppression. */
export interface SourceExclusion {
  exclusionType: "PATH" | "RULE" | "FILE_FINGERPRINT" | "FINDING_FINGERPRINT" | "DEPENDENCY";
  pattern: string;
  reason: string;
  createdBy: string;
}
