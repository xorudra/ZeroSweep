/**
 * Prompt 35 — Mobile & Binary Security V2 shared types (§13–§15,
 * §105–§108, §121–§126).
 *
 * This module DEEPENS Prompts 17/18 on the same canonical records.
 * Nothing here executes anything: plans are governed snapshots,
 * carry-forward rows are classifications, coverage rows are honest
 * accounts of what was examined. Artifacts are never installed, run,
 * emulated or executed — static analysis only (§164).
 */

export type MobbinPlatform = "ANDROID" | "IOS";

/** §15: the closed V2 analysis-profile set. */
export const MOBBIN_PROFILES = [
  "MOBILE_STATIC",
  "MOBILE_STANDARD",
  "ANDROID_STATIC",
  "ANDROID_DYNAMIC_SAFE",
  "IOS_STATIC",
  "IOS_DYNAMIC_SAFE",
  "BINARY_STATIC",
  "BINARY_HARDENING",
  "TARGETED_MOBILE_VERIFICATION",
] as const;
export type MobbinProfile = (typeof MOBBIN_PROFILES)[number];

/** Static pipeline modules (§14 orchestrator stages, analysis side). */
export const MOBBIN_STATIC_MODULES = [
  "INGEST",
  "CLASSIFY",
  "MANIFEST_ANALYSIS",
  "STATIC_ANALYSIS",
  "DEPENDENCY_ANALYSIS",
  "SECRET_ANALYSIS",
  "BINARY_HARDENING",
  "CRYPTO_ANALYSIS",
  "STORAGE_ANALYSIS",
  "WEBVIEW_ANALYSIS",
  "NETWORK_CONFIG_ANALYSIS",
] as const;
export type MobbinStaticModule = (typeof MOBBIN_STATIC_MODULES)[number];

/** Dynamic modules (§14 OPTIONAL_DYNAMIC_ANALYSIS + traffic). Every
 *  one of these requires an explicitly authorized app + device + lab
 *  (§71) — they are never part of a default plan (§16). */
export const MOBBIN_DYNAMIC_MODULES = [
  "RUNTIME_OBSERVATION",
  "TRAFFIC_ANALYSIS",
  "DYNAMIC_STORAGE_ANALYSIS",
  "LOG_EXPOSURE_ANALYSIS",
] as const;
export type MobbinDynamicModule = (typeof MOBBIN_DYNAMIC_MODULES)[number];

export interface MobbinProfileDefinition {
  profile: MobbinProfile;
  platform: MobbinPlatform | "BINARY" | "ANY";
  staticModules: MobbinStaticModule[];
  dynamicModules: MobbinDynamicModule[];
  /** Dynamic modules in this profile need the §71 gate. */
  dynamic: boolean;
  description: string;
}

/** §13: a governed mobile analysis plan (persisted as
 *  MobileAnalysisPlan). The plan is a snapshot of intent + gate
 *  verdicts — creating one never starts a device, a proxy or an
 *  instrument (§12/§16). */
export interface MobileAnalysisPlanV2 {
  profile: MobbinProfile;
  platform: MobbinPlatform;
  artifactHash: string;
  authorizationId: string | null;
  staticModules: MobbinStaticModule[];
  dynamicModules: MobbinDynamicModule[];
  dynamicGate: "NOT_REQUESTED" | "ALLOWED" | "BLOCKED";
  dynamicGateReasons: string[];
  deviceProfile: { deviceId: string; deviceType: string } | null;
  trafficAnalysis: boolean;
  limits: { maxFindings: number; maxStrings: number; maxComponents: number };
  verificationPolicy: "TARGETED_RETEST" | "MANUAL_REVIEW";
}

/** §106: finding carry-forward classifications across a version edge. */
export type CarryForwardClassification = "NEW" | "PERSISTING" | "FIXED_CANDIDATE" | "REGRESSED";

export interface CarryForwardFindingRef {
  /** Cross-build fingerprint (Prompt 17 §policy crossBuildKeyFor) —
   *  the stable identity of an issue across builds. */
  crossBuildFingerprint: string;
  findingId: string;
  ruleId: string | null;
  title: string;
  severity: string;
  /** Lifecycle status on the finding (RESOLVED etc.) — used only to
   *  detect regressions of previously-closed issues. */
  status: string;
}

export interface CarryForwardEntry {
  crossBuildFingerprint: string;
  classification: CarryForwardClassification;
  fromFindingId: string | null;
  toFindingId: string | null;
  ruleId: string | null;
  title: string;
  severity: string;
  /** §107: how a FIXED_CANDIDATE may be verified — always the
   *  governed Prompt 31 targeted retest, never the lineage itself. */
  verification: "TARGETED_RETEST_REQUIRED" | null;
}

export interface CarryForwardResult {
  entries: CarryForwardEntry[];
  summary: Record<CarryForwardClassification, number>;
}

/** §122: the closed mobile coverage dimension set. */
export const MOBILE_COVERAGE_DIMENSIONS = [
  "MANIFEST",
  "PERMISSIONS",
  "COMPONENTS",
  "CODE_RULES",
  "DEPENDENCIES",
  "SECRETS",
  "NATIVE_LIBRARIES",
  "DYNAMIC_MODULES",
  "TRAFFIC",
] as const;
export type MobileCoverageDimension = (typeof MOBILE_COVERAGE_DIMENSIONS)[number];

/** §123: the closed binary coverage dimension set. */
export const BINARY_COVERAGE_DIMENSIONS = [
  "FORMAT_PARSING",
  "HARDENING",
  "IMPORTS_EXPORTS",
  "STRINGS",
  "FUNCTIONS",
  "DEPENDENCY_ANALYSIS",
  "DECOMPILATION",
] as const;
export type BinaryCoverageDimension = (typeof BINARY_COVERAGE_DIMENSIONS)[number];

export type CoverageDimensionStatus = "COVERED" | "NOT_COVERED" | "NOT_APPLICABLE";
export interface CoverageDimensionResult {
  status: CoverageDimensionStatus;
  detail: string;
}
export type MobbinCoverageResult<D extends string> = {
  dimensions: Record<D, CoverageDimensionResult>;
  /** §124: any gap ⇒ COMPLETED_WITH_GAPS — never reported clean. */
  completion: "COMPLETED" | "COMPLETED_WITH_GAPS";
};

/** §125/§126: obfuscation / packing evidence. Detection is recorded
 *  with confidence; protected artifacts are never unpacked (§126)
 *  and coverage never claims full code visibility (§125). */
export interface ProtectionEvidence {
  detected: boolean;
  confidence: "NONE" | "LOW" | "MEDIUM" | "HIGH";
  signals: string[];
}
