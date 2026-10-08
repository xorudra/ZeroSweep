/**
 * Web/API VAPT V2 shared types (Prompt 32).
 *
 * V2 deepens the Prompt 5–9 engines; it does not replace them. Every
 * type here feeds the EXISTING governance chain: verified target +
 * approved assessment + scope + policy (Prompt 4/7/9/16). Nothing in
 * this module can authorize a target, widen scope, or raise a tool's
 * risk class — it only describes governed work more precisely.
 */

/** §15: tool risk classes. There is deliberately NO destructive class. */
export type ToolRiskClass = "PASSIVE" | "LOW" | "MODERATE" | "HIGH";

export const TOOL_RISK_CLASSES: readonly ToolRiskClass[] = ["PASSIVE", "LOW", "MODERATE", "HIGH"];

/** §5: target environments. */
export type TargetEnvironment = "PRODUCTION" | "STAGING" | "DEVELOPMENT" | "TEST" | "UNKNOWN";

/** §8: preflight outcomes. */
export type PreflightStatus = "READY" | "READY_WITH_WARNINGS" | "BLOCKED" | "UNREACHABLE" | "AUTH_REQUIRED";

/** §122: V2 scan profiles. */
export type WebVaptProfileKey =
  | "WEB_PASSIVE" | "WEB_SAFE" | "WEB_STANDARD"
  | "API_SAFE" | "API_STANDARD"
  | "TLS_ONLY" | "CONTENT_DISCOVERY" | "TARGETED_VERIFICATION";

export const WEB_VAPT_PROFILES: readonly WebVaptProfileKey[] = [
  "WEB_PASSIVE", "WEB_SAFE", "WEB_STANDARD", "API_SAFE", "API_STANDARD",
  "TLS_ONLY", "CONTENT_DISCOVERY", "TARGETED_VERIFICATION",
];

/** §48/§126: every active plan carries an explicit request budget. */
export interface ScanRequestBudget {
  maxRequests: number;
  maxRequestsPerSecond: number;
  maxConcurrency: number;
  maxDurationSeconds: number;
  maxResponseBytes: number;
}

/** §149: why a test did not run — recorded, never silently dropped. */
export type SkippedReason =
  | "NOT_AUTHORIZED" | "AUTH_UNAVAILABLE" | "BUDGET_EXHAUSTED"
  | "UNSUPPORTED" | "TOOL_UNAVAILABLE" | "POLICY_BLOCKED";

export const SKIPPED_REASONS: readonly SkippedReason[] = [
  "NOT_AUTHORIZED", "AUTH_UNAVAILABLE", "BUDGET_EXHAUSTED",
  "UNSUPPORTED", "TOOL_UNAVAILABLE", "POLICY_BLOCKED",
];

/** §151: V2 scan lifecycle states. */
export type WebVaptScanStatus =
  | "QUEUED" | "PREFLIGHT" | "RUNNING" | "COMPLETED"
  | "COMPLETED_WITH_GAPS" | "FAILED" | "CANCELLED" | "BLOCKED";

/** §110: finding confidence bands (evidence-based, never multiplied). */
export type FindingConfidenceBand = "LOW" | "MEDIUM" | "HIGH" | "VERIFIED";

/** §32: parameter locations. */
export type ParameterLocation = "QUERY" | "PATH" | "HEADER" | "COOKIE" | "BODY" | "FORM" | "JSON" | "XML";

/** §14: one tool's capability record in the V2 registry view. */
export interface ToolCapabilityRecord {
  slug: string;
  name: string;
  version?: string;
  category: string;
  capabilities: string[];
  /** true = the tool only observes/imports; false = it sends requests. */
  passive: boolean;
  supportedTargetTypes: string[];
  authenticationSupport: boolean;
  riskClass: ToolRiskClass;
  defaultTimeoutSeconds: number;
  resourceProfile: { cpu: string; memory: string };
  /** Adapter/parser versions (§144) — provenance for every result. */
  adapterVersion: string;
  parserVersion: string;
}
