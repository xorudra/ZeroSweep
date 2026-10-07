// Shared application types. Keep API contracts explicit here; never import
// backend implementation details into the frontend.

export const ROLES = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"] as const;
export type Role = (typeof ROLES)[number];

export const TARGET_TYPES = [
  "DOMAIN", "WEB_APPLICATION", "IP_ADDRESS", "CIDR", "API", "GRAPHQL",
  "SOURCE_REPOSITORY", "APK", "CONTAINER_IMAGE", "DOCKER", "KUBERNETES",
  "AWS", "AZURE", "GCP", "ACTIVE_DIRECTORY", "BINARY", "WIRELESS_LAB",
] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export const ASSESSMENT_PROFILES = [
  "PASSIVE_RECON", "WEB_BASELINE", "WEB_COMPREHENSIVE", "API_ASSESSMENT",
  "NETWORK_ASSESSMENT",
  // Prompt 10 §8: dedicated network profiles.
  "NETWORK_DISCOVERY", "NETWORK_BASELINE", "NETWORK_COMPREHENSIVE", "NETWORK_INTERNAL",
  "SOURCE_CODE", "CONTAINER", "CLOUD", "MOBILE", "CUSTOM",
  // Prompt 12 §18: source code security profiles. SOURCE_CODE remains as
  // the legacy alias and resolves to the SOURCE_BASELINE stage chain.
  "SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SAST_ONLY",
] as const;
export type AssessmentProfile = (typeof ASSESSMENT_PROFILES)[number];

export const SCAN_STATUSES = [
  "CREATED", "QUEUED", "PREPARING", "RUNNING", "PAUSING", "PAUSED",
  "CANCELLING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED",
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

/**
 * Legal scan state transitions (Prompt 4 §17). PAUSING/CANCELLING are explicit
 * intermediate states so pause/cancel are cooperative and observable; a scan
 * may never jump outside this map (e.g. COMPLETED -> RUNNING always fails).
 */
export const SCAN_TRANSITIONS: Readonly<Record<ScanStatus, readonly ScanStatus[]>> = {
  CREATED: ["QUEUED", "CANCELLED", "FAILED"],
  QUEUED: ["PREPARING", "CANCELLING", "CANCELLED", "FAILED"],
  PREPARING: ["RUNNING", "CANCELLING", "CANCELLED", "FAILED"],
  RUNNING: ["PAUSING", "PAUSED", "CANCELLING", "CANCELLED", "COMPLETED", "PARTIAL", "FAILED"],
  PAUSING: ["PAUSED", "CANCELLING", "FAILED"],
  PAUSED: ["RUNNING", "CANCELLING", "CANCELLED", "FAILED"],
  CANCELLING: ["CANCELLED", "FAILED"],
  COMPLETED: [],
  PARTIAL: [],
  FAILED: [],
  CANCELLED: [],
};

export function canTransitionScan(from: ScanStatus, to: ScanStatus): boolean {
  return SCAN_TRANSITIONS[from].includes(to);
}

export class InvalidScanTransitionError extends Error {
  constructor(from: ScanStatus, to: ScanStatus) {
    super(`Invalid scan state transition: ${from} -> ${to}`);
    this.name = "InvalidScanTransitionError";
  }
}

export function assertScanTransition(from: ScanStatus, to: ScanStatus): void {
  if (!canTransitionScan(from, to)) throw new InvalidScanTransitionError(from, to);
}

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = ["OPEN", "CONFIRMED", "ACCEPTED_RISK", "RESOLVED", "FALSE_POSITIVE"] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const VERIFICATION_STATUSES = ["UNVERIFIED", "LIKELY", "CONFIRMED", "REJECTED"] as const;
export type VerificationStatus = (typeof VERIFICATION_STATUSES)[number];

export interface AuthenticatedUser {
  id: string;
  email: string;
  organizationId: string;
  role: Role;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

export interface HealthCheck {
  status: "ok" | "degraded" | "down";
  checks: Record<string, { status: "ok" | "down" | "skipped"; detail?: string }>;
}
