/**
 * Onboarding, abuse prevention, product analytics privacy, diagnostics
 * redaction, upgrade preflight and version compatibility
 * (Prompt 40 §65–§75, §141–§147, §169–§175, §190–§210).
 */
import { FAIR_USE_CEILINGS } from "./usage";

// ---------------------------------------------------------------------------
// Onboarding (§65–§75)
// ---------------------------------------------------------------------------

export interface OnboardingStepDefinition {
  key: string;
  title: string;
  optional: boolean;
  /** Security-critical steps can never be skipped (§69/§70). */
  securityCritical: boolean;
}

export const ONBOARDING_STEPS: OnboardingStepDefinition[] = [
  { key: "WELCOME", title: "Welcome", optional: false, securityCritical: false },
  { key: "ORGANIZATION_PROFILE", title: "Organization Profile", optional: false, securityCritical: false },
  { key: "WORKSPACE_SETUP", title: "Workspace Setup", optional: false, securityCritical: false },
  { key: "TEAM_INVITATION", title: "Team Invitation", optional: true, securityCritical: false },
  { key: "SECURITY_SCOPE", title: "Security Scope & Authorization", optional: false, securityCritical: true },
  { key: "ASSET_SETUP", title: "Asset Setup", optional: false, securityCritical: false },
  { key: "INTEGRATION_SETUP", title: "Integration Setup", optional: true, securityCritical: false },
  { key: "FIRST_ASSESSMENT", title: "First Assessment", optional: false, securityCritical: true },
  { key: "FIRST_REPORT", title: "First Report", optional: true, securityCritical: false },
  { key: "COMPLETION", title: "Completion", optional: false, securityCritical: false },
];

/** Default onboarding assessment profile is the SAFE standard profile (§72).
 *  High-impact modes are never a one-click onboarding shortcut (§73). */
export const ONBOARDING_DEFAULT_ASSESSMENT_PROFILE = "SAFE_STANDARD";

export function onboardingProgress(completedSteps: string[]): { completed: number; total: number; percent: number; nextStep: string | null } {
  const done = new Set(completedSteps);
  const total = ONBOARDING_STEPS.length;
  const completed = ONBOARDING_STEPS.filter((s) => done.has(s.key)).length;
  const next = ONBOARDING_STEPS.find((s) => !done.has(s.key));
  return { completed, total, percent: Math.round((completed / total) * 100), nextStep: next?.key ?? null };
}

export function canCompleteStep(stepKey: string, completedSteps: string[]): { ok: boolean; reason?: string } {
  const def = ONBOARDING_STEPS.find((s) => s.key === stepKey);
  if (!def) return { ok: false, reason: `Unknown onboarding step '${stepKey}'.` };
  const idx = ONBOARDING_STEPS.indexOf(def);
  const missing = ONBOARDING_STEPS.slice(0, idx).filter((s) => !s.optional && !completedSteps.includes(s.key));
  if (missing.length > 0) return { ok: false, reason: `Complete required steps first: ${missing.map((s) => s.key).join(", ")}.` };
  return { ok: true };
}

// ---------------------------------------------------------------------------
// Abuse prevention (§169–§175)
// ---------------------------------------------------------------------------

export const ABUSE_SIGNALS = [
  "REPEATED_OUT_OF_SCOPE_REQUESTS",
  "EXTREME_TARGET_CHURN",
  "AUTHORIZATION_FAILURES",
  "PROTECTED_TARGET_ATTEMPT",
  "QUOTA_ABUSE",
  "SCANNER_POLICY_VIOLATIONS",
] as const;
export type AbuseSignal = (typeof ABUSE_SIGNALS)[number];

export const ABUSE_RESPONSES = ["NONE", "WARN", "THROTTLE", "BLOCK_SCAN_CREATION", "REQUIRE_REVIEW"] as const;
export type AbuseResponse = (typeof ABUSE_RESPONSES)[number];

/**
 * Signals are indicators, not proof of malicious intent (§172): the
 * response ladder escalates with repetition and always leaves a human
 * review path. Nothing here auto-declares guilt or deletes data.
 */
export function evaluateAbuseResponse(signalCounts: Partial<Record<AbuseSignal, number>>): { response: AbuseResponse; reason: string } {
  const protectedAttempts = signalCounts.PROTECTED_TARGET_ATTEMPT ?? 0;
  if (protectedAttempts > 0) {
    return { response: "BLOCK_SCAN_CREATION", reason: "Attempt to target protected platform infrastructure; scan creation blocked pending review (§173)." };
  }
  const total = Object.values(signalCounts).reduce((a, b) => a + (b ?? 0), 0);
  if (total >= 20) return { response: "REQUIRE_REVIEW", reason: "Sustained abuse-signal volume requires human review (§171)." };
  if (total >= 10) return { response: "BLOCK_SCAN_CREATION", reason: "Repeated abuse signals; scan creation temporarily blocked (§171)." };
  if (total >= 5) return { response: "THROTTLE", reason: "Elevated abuse signals; actions throttled (§171)." };
  if (total >= 1) return { response: "WARN", reason: "Abuse signal recorded; signals are indicators, not proof of intent (§172)." };
  return { response: "NONE", reason: "No abuse signals." };
}

/**
 * Platform protected targets (§173) and cloud metadata endpoints (§174):
 * tenant scans must never target these. (The SDK scope engine also
 * refuses private/reserved ranges; this list is the product-level
 * explicit deny set.)
 */
export const PROTECTED_TARGET_IDENTIFIERS: readonly string[] = [
  "169.254.169.254",
  "metadata.google.internal",
  "metadata.google",
  "100.100.100.200", // Alibaba metadata
  "fd00:ec2::254", // AWS IMDS IPv6
];

export function isProtectedTarget(identifier: string): boolean {
  const v = identifier.trim().toLowerCase();
  return PROTECTED_TARGET_IDENTIFIERS.some((p) => v === p || v.endsWith(`/${p}`) || v.includes(`://${p}`));
}

// ---------------------------------------------------------------------------
// Product analytics privacy (§141–§147, §229)
// ---------------------------------------------------------------------------

export const PRODUCT_ANALYTICS_EVENTS = [
  "SIGNUP_COMPLETED",
  "ONBOARDING_COMPLETED",
  "FIRST_ASSET",
  "FIRST_SCAN",
  "FIRST_FINDING",
  "FIRST_REPORT",
  "FEATURE_ADOPTION",
] as const;
export type ProductAnalyticsEventType = (typeof PRODUCT_ANALYTICS_EVENTS)[number];

/** Keys that must NEVER reach product analytics (§143). */
const FORBIDDEN_ANALYTICS_KEY_PATTERN = /(target|url|host|domain|ip|email|evidence|finding|vulnerab|credential|secret|token|password|payload|report_content|scan_result)/i;

/**
 * Privacy filter for analytics properties (§143/§229): only aggregate,
 * non-sensitive scalar metadata survives. Anything resembling a target,
 * evidence, credential or finding payload is dropped, and the drop is
 * reported so callers can audit it.
 */
export function sanitizeAnalyticsProperties(input: Record<string, unknown>): { properties: Record<string, unknown>; droppedKeys: string[] } {
  const properties: Record<string, unknown> = {};
  const droppedKeys: string[] = [];
  for (const [key, value] of Object.entries(input)) {
    if (FORBIDDEN_ANALYTICS_KEY_PATTERN.test(key)) { droppedKeys.push(key); continue; }
    if (typeof value === "string" && (value.includes("://") || /^[\w.-]+\.[a-z]{2,}$/i.test(value) || value.includes("@"))) {
      droppedKeys.push(key); continue; // looks like a URL/domain/email — never analytics data
    }
    if (typeof value === "number" || typeof value === "boolean" || value === null) properties[key] = value;
    else if (typeof value === "string" && value.length <= 64) properties[key] = value;
    else droppedKeys.push(key);
  }
  return { properties, droppedKeys };
}

// ---------------------------------------------------------------------------
// Diagnostics (§206–§210, §230)
// ---------------------------------------------------------------------------

const SECRET_KEY_PATTERN = /(secret|password|passwd|token|api[-_]?key|private[-_]?key|credential|authorization|cookie)/i;
const SECRET_VALUE_PATTERN = /(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|Bearer\s+[A-Za-z0-9._-]{10,})/;

/**
 * Redact a configuration snapshot for a diagnostic bundle (§208):
 * keys are listed (operators need to know WHAT is configured) but
 * secret values never are (§230).
 */
export function redactConfigForDiagnostics(config: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(config)) {
    if (SECRET_KEY_PATTERN.test(key)) { out[key] = value ? "[configured]" : "[unset]"; continue; }
    if (typeof value === "string" && SECRET_VALUE_PATTERN.test(value)) { out[key] = "[redacted]"; continue; }
    out[key] = value;
  }
  return out;
}

export function sanitizeDiagnosticText(text: string): string {
  return text.replace(SECRET_VALUE_PATTERN, "[redacted]");
}

export interface DiagnosticBundleInput {
  releaseVersion: string;
  productMode: string;
  generatedAt: Date;
  serviceHealth: Record<string, string>;
  workerHealth: Array<{ id: string; status: string; version?: string }>;
  queueStatus: Array<{ name: string; waiting: number; active: number; failed: number }>;
  configuration: Record<string, unknown>;
  recentErrors: string[];
}

export interface DiagnosticBundle {
  kind: "DSRCLONE_SUPPORT_DIAGNOSTICS";
  releaseVersion: string;
  productMode: string;
  generatedAt: string;
  serviceHealth: Record<string, string>;
  workerHealth: Array<{ id: string; status: string; version?: string }>;
  queueStatus: Array<{ name: string; waiting: number; active: number; failed: number }>;
  configuration: Record<string, unknown>;
  recentErrors: string[];
  note: string;
}

/** Build a redacted support bundle (§207). Generation is always an
 *  explicit user/operator action (§209) — bundles are never uploaded
 *  automatically and contain no customer content. */
export function buildDiagnosticBundle(input: DiagnosticBundleInput): DiagnosticBundle {
  return {
    kind: "DSRCLONE_SUPPORT_DIAGNOSTICS",
    releaseVersion: input.releaseVersion,
    productMode: input.productMode,
    generatedAt: input.generatedAt.toISOString(),
    serviceHealth: input.serviceHealth,
    workerHealth: input.workerHealth,
    queueStatus: input.queueStatus,
    configuration: redactConfigForDiagnostics(input.configuration),
    recentErrors: input.recentErrors.slice(0, 50).map(sanitizeDiagnosticText),
    note: "Secrets, tokens, target evidence and customer content are excluded by construction (§208).",
  };
}

// ---------------------------------------------------------------------------
// Upgrade preflight & compatibility (§190–§200)
// ---------------------------------------------------------------------------

export interface UpgradePreflightFacts {
  currentVersion: string;
  targetVersion: string;
  pendingMigrations: number;
  latestBackupStatus: "SUCCESS" | "FAILED" | "NONE";
  latestBackupAgeHours: number | null;
  freeDiskBytes: number;
  requiredDiskBytes: number;
  workerVersions: string[];
  compatibleWorkerVersions: string[];
  deprecatedSettingsPresent: string[];
}

export interface UpgradePreflightResult {
  canUpgrade: boolean;
  blockers: string[];
  warnings: string[];
}

/** §190–§193: unsafe upgrades are BLOCKED when mandatory preconditions fail. */
export function evaluateUpgradePreflight(facts: UpgradePreflightFacts): UpgradePreflightResult {
  const blockers: string[] = [];
  const warnings: string[] = [];
  if (facts.currentVersion === facts.targetVersion) blockers.push("Target version equals current version; nothing to upgrade.");
  if (facts.latestBackupStatus !== "SUCCESS") blockers.push("No successful backup exists; a verified backup is required before upgrade (§193).");
  else if (facts.latestBackupAgeHours !== null && facts.latestBackupAgeHours > 24) warnings.push(`Latest backup is ${Math.round(facts.latestBackupAgeHours)}h old; take a fresh backup before upgrading (§193).`);
  if (facts.freeDiskBytes < facts.requiredDiskBytes) blockers.push("Insufficient free disk/storage for the upgrade (§191).");
  const incompatible = facts.workerVersions.filter((v) => !facts.compatibleWorkerVersions.includes(v));
  if (incompatible.length > 0) blockers.push(`Incompatible worker versions detected: ${[...new Set(incompatible)].join(", ")} (§195).`);
  if (facts.pendingMigrations < 0) blockers.push("Migration state could not be determined.");
  if (facts.deprecatedSettingsPresent.length > 0) warnings.push(`Deprecated settings present: ${facts.deprecatedSettingsPresent.join(", ")} (§191).`);
  return { canUpgrade: blockers.length === 0, blockers, warnings };
}

/** Version support matrix (§194–§200). Mirrors docs/product/support-matrix.md. */
export const SUPPORT_MATRIX = {
  product: "1.0.0",
  api: "v1",
  postgresql: ["15", "16"],
  redis: ["7"],
  node: ["20", "22"],
  browsers: ["Chrome (last 2)", "Edge (last 2)", "Firefox (last 2)", "Safari (last 2)"],
  workerProtocol: "1",
  toolVersionPolicy: "Tool Registry marks scanner versions outside the supported range as unsupported (§196).",
} as const;

export function isWorkerVersionCompatible(workerVersion: string): boolean {
  return workerVersion === SUPPORT_MATRIX.workerProtocol || workerVersion.startsWith("1.");
}

export { FAIR_USE_CEILINGS };
