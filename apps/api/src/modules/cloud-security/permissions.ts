import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Cloud-security permissions (Prompt 14 §88). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is DSRclone policy and lives in exactly one place.
 * Managing accounts is administrative; raw artifact (resource
 * configuration) access is OWNER/ADMIN and audited per access (§103).
 */
export const CLOUD_SECURITY_PERMISSIONS = [
  "VIEW_CLOUD_SECURITY",
  "MANAGE_CLOUD_ACCOUNTS",
  "RUN_CLOUD_SCAN",
  "VIEW_CLOUD_IAM",
  "VIEW_CLOUD_GRAPH",
  "VIEW_CLOUD_ARTIFACTS",
  "MANAGE_CLOUD_POLICIES",
  "VIEW_CLOUD_COMPLIANCE",
] as const;
export type CloudSecurityPermission = (typeof CLOUD_SECURITY_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<CloudSecurityPermission, Role[]> = {
  VIEW_CLOUD_SECURITY: ALL,
  MANAGE_CLOUD_ACCOUNTS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  RUN_CLOUD_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_CLOUD_IAM: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_CLOUD_GRAPH: ALL,
  VIEW_CLOUD_ARTIFACTS: ["OWNER", "ADMIN"],
  MANAGE_CLOUD_POLICIES: ["OWNER", "ADMIN"],
  VIEW_CLOUD_COMPLIANCE: ALL,
};

export function hasCloudSecurityPermission(user: RequestUser, permission: CloudSecurityPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireCloudSecurityPermission(user: RequestUser, permission: CloudSecurityPermission): void {
  if (!hasCloudSecurityPermission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
