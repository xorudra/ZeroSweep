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
  "NETWORK_ASSESSMENT", "SOURCE_CODE", "CONTAINER", "CLOUD", "MOBILE", "CUSTOM",
] as const;
export type AssessmentProfile = (typeof ASSESSMENT_PROFILES)[number];

export const SCAN_STATUSES = [
  "QUEUED", "PREPARING", "RUNNING", "PAUSED", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED",
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

/** Legal scan state transitions. A scan may never jump outside this map. */
export const SCAN_TRANSITIONS: Readonly<Record<ScanStatus, readonly ScanStatus[]>> = {
  QUEUED: ["PREPARING", "CANCELLED", "FAILED"],
  PREPARING: ["RUNNING", "FAILED", "CANCELLED"],
  RUNNING: ["PAUSED", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED"],
  PAUSED: ["RUNNING", "CANCELLED", "FAILED"],
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
