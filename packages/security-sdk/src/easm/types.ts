/**
 * EASM shared types (Prompt 29). The authorization boundary is the
 * core invariant of this module: DISCOVERED ≠ OWNERSHIP_CANDIDATE ≠
 * VERIFIED_OWNED ≠ AUTHORIZED_FOR_ACTIVE_TESTING. Nothing in this
 * package ever promotes a value across that boundary by itself —
 * promotion and authorization are workflow decisions recorded by the
 * API layer with named human (or policy) evidence.
 */

export const EASM_PROGRAM_STATUSES = ["DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"] as const;
export type EasmProgramStatus = (typeof EASM_PROGRAM_STATUSES)[number];

export const EASM_ROOT_ASSET_TYPES = ["DOMAIN", "IP", "CIDR", "CLOUD_ACCOUNT", "REPOSITORY_ORGANIZATION"] as const;
export type EasmRootAssetType = (typeof EASM_ROOT_ASSET_TYPES)[number];

/** §7 root-asset authorization states. */
export const EASM_AUTHORIZATION_STATES = ["PENDING", "VERIFIED", "REJECTED", "EXPIRED"] as const;
export type EasmAuthorizationState = (typeof EASM_AUTHORIZATION_STATES)[number];

/** §11 discovery modes. CUSTOM stays bounded by platform policy. */
export const EASM_DISCOVERY_MODES = ["PASSIVE_ONLY", "SAFE_ACTIVE", "CUSTOM"] as const;
export type EasmDiscoveryMode = (typeof EASM_DISCOVERY_MODES)[number];

/** §17 candidate review status. */
export const EASM_CANDIDATE_STATUSES = ["NEW", "REVIEWING", "CONFIRMED", "REJECTED", "MERGED"] as const;
export type EasmCandidateStatus = (typeof EASM_CANDIDATE_STATUSES)[number];

/** §18 ownership status (a classification, never a permission). */
export const EASM_OWNERSHIP_STATUSES = ["UNKNOWN", "LIKELY", "VERIFIED", "THIRD_PARTY", "SHARED"] as const;
export type EasmOwnershipStatus = (typeof EASM_OWNERSHIP_STATUSES)[number];

/** §66 ownership confidence ladder. */
export const EASM_OWNERSHIP_CONFIDENCES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "VERIFIED"] as const;
export type EasmOwnershipConfidence = (typeof EASM_OWNERSHIP_CONFIDENCES)[number];

/** §19 active-testing status. There is deliberately NO unrestricted mode. */
export const EASM_ACTIVE_TESTING_STATUSES = ["NOT_AUTHORIZED", "AUTHORIZED_SAFE", "AUTHORIZED_STANDARD"] as const;
export type EasmActiveTestingStatus = (typeof EASM_ACTIVE_TESTING_STATUSES)[number];

/** §91 asset lifecycle. DISAPPEARED requires a confirmation policy (§92). */
export const EASM_ASSET_LIFECYCLES = ["DISCOVERED", "ACTIVE", "STALE", "DISAPPEARED", "ARCHIVED"] as const;
export type EasmAssetLifecycle = (typeof EASM_ASSET_LIFECYCLES)[number];

/** §74 internet exposure classification. */
export const EASM_EXPOSURE_STATES = ["NOT_OBSERVED", "INTERNET_EXPOSED", "CONDITIONALLY_EXPOSED", "UNKNOWN"] as const;
export type EasmExposureState = (typeof EASM_EXPOSURE_STATES)[number];

/** §38 certificate health states. */
export const EASM_CERTIFICATE_STATES = ["HEALTHY", "EXPIRING", "URGENT", "EXPIRED"] as const;
export type EasmCertificateState = (typeof EASM_CERTIFICATE_STATES)[number];

/** §55 technology categories. */
export const EASM_TECHNOLOGY_CATEGORIES = [
  "WEB_SERVER", "FRAMEWORK", "CMS", "LANGUAGE", "CDN", "WAF", "ANALYTICS", "DATABASE_HINT", "CLOUD_SERVICE", "OTHER",
] as const;
export type EasmTechnologyCategory = (typeof EASM_TECHNOLOGY_CATEGORIES)[number];

/** §56 technology confidence. */
export const EASM_TECHNOLOGY_CONFIDENCES = ["LOW", "MEDIUM", "HIGH"] as const;
export type EasmTechnologyConfidence = (typeof EASM_TECHNOLOGY_CONFIDENCES)[number];

/** §81 drift types. */
export const EASM_DRIFT_TYPES = [
  "ASSET_ADDED", "ASSET_REMOVED", "DNS_CHANGED", "IP_CHANGED", "SERVICE_ADDED", "SERVICE_REMOVED",
  "HTTP_CHANGED", "CERTIFICATE_CHANGED", "TECHNOLOGY_CHANGED", "EXPOSURE_CHANGED", "OWNERSHIP_CHANGED",
] as const;
export type EasmDriftType = (typeof EASM_DRIFT_TYPES)[number];

/** §78 EASM risk-signal kinds. Signals are CONTEXT for RiskEngine V3
 *  (§77) — they never overwrite canonical finding severity. */
export const EASM_RISK_SIGNAL_KINDS = [
  "NEW_PUBLIC_ASSET", "UNKNOWN_PUBLIC_ASSET", "PUBLIC_CRITICAL_ASSET", "PUBLIC_KEV",
  "PUBLIC_CRITICAL_FINDING", "PUBLIC_SENSITIVE_SERVICE", "OUTDATED_PUBLIC_TECHNOLOGY",
  "EXPIRING_PUBLIC_CERTIFICATE", "DANGLING_DNS_CANDIDATE",
] as const;
export type EasmRiskSignalKind = (typeof EASM_RISK_SIGNAL_KINDS)[number];

/** §128 discovery run statuses. */
export const EASM_RUN_STATUSES = ["QUEUED", "RUNNING", "PARTIAL", "COMPLETED", "FAILED", "CANCELLED"] as const;
export type EasmRunStatus = (typeof EASM_RUN_STATUSES)[number];

/** Discovery source kinds. Every source is a governed transport:
 *  PASSIVE sources never touch the candidate; ACTIVE kinds run only
 *  against roots whose active testing is authorized (§41/§47). */
export const EASM_SOURCE_KINDS = [
  "AMASS_PASSIVE", "SUBFINDER", "ASSETFINDER", "FINDOMAIN", "CERT_TRANSPARENCY",
  "DNS_RESOLUTION", "DNS_ZONE_OBSERVATION", "TLS_HANDSHAKE", "HTTP_PROBE", "SERVICE_DISCOVERY",
  "TECHNOLOGY_DETECTION", "HISTORICAL_URLS", "MANUAL_IMPORT",
] as const;
export type EasmSourceKind = (typeof EASM_SOURCE_KINDS)[number];

export const EASM_ACTIVE_SOURCE_KINDS: readonly EasmSourceKind[] = [
  "DNS_RESOLUTION", "TLS_HANDSHAKE", "HTTP_PROBE", "SERVICE_DISCOVERY",
];

/** §61 URL path classification (deterministic heuristics only — a
 *  classification is never a vulnerability claim). */
export const EASM_URL_CLASSES = ["API", "AUTH", "ADMIN", "UPLOAD", "STATIC", "UNKNOWN"] as const;
export type EasmUrlClass = (typeof EASM_URL_CLASSES)[number];
