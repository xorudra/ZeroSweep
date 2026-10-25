import { ForbiddenException } from "@nestjs/common";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Cloud Security V2 permissions (Prompt 34 §139). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is ZeroSweep policy and lives in exactly one place.
 * RUN_CLOUD_ASSESSMENT is the V2 name for starting an orchestrated
 * assessment; Prompt 14's RUN_CLOUD_SCAN remains the scan permission.
 */
export const CLOUD_V2_PERMISSIONS = [
  "VIEW_CLOUD_SECURITY",
  "MANAGE_CLOUD_ACCOUNTS",
  "RUN_CLOUD_ASSESSMENT",
  "VIEW_CLOUD_IAM",
  "VIEW_CLOUD_EVIDENCE",
  "VIEW_CLOUD_ATTACK_PATHS",
  "EXPORT_CLOUD_SECURITY_REPORT",
] as const;
export type CloudV2Permission = (typeof CLOUD_V2_PERMISSIONS)[number];

type Role = RequestUser["role"];
const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<CloudV2Permission, Role[]> = {
  VIEW_CLOUD_SECURITY: ALL,
  MANAGE_CLOUD_ACCOUNTS: ADMINS,
  RUN_CLOUD_ASSESSMENT: LEADS,
  VIEW_CLOUD_IAM: STAFF,
  VIEW_CLOUD_EVIDENCE: LEADS,
  VIEW_CLOUD_ATTACK_PATHS: ALL,
  EXPORT_CLOUD_SECURITY_REPORT: STAFF,
};

export function requireCloudV2Permission(user: RequestUser, permission: CloudV2Permission): void {
  if (!MAP[permission].includes(user.role)) {
    throw new ForbiddenException(`Role ${user.role} lacks ${permission} (Prompt 34 §139)`);
  }
}

export function cloudV2PermissionsFor(role: Role): CloudV2Permission[] {
  return CLOUD_V2_PERMISSIONS.filter((p) => MAP[p].includes(role));
}
