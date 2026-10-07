import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Mobile security permissions (Prompt 17 §101). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is DSRclone policy and lives in exactly one place.
 * Decompiled-source artifacts are sensitive (§24): OWNER/ADMIN/
 * SECURITY_ENGINEER only, audited per access (§116). Instrumentation
 * approval is administrator-class (§71). Device-lab management is
 * administrative (§98).
 */
export const MOBILE_SECURITY_PERMISSIONS = [
  "VIEW_MOBILE_SECURITY",
  "MANAGE_MOBILE_APPS",
  "UPLOAD_MOBILE_BUILD",
  "RUN_MOBILE_STATIC_SCAN",
  "RUN_MOBILE_DYNAMIC_SCAN",
  "APPROVE_MOBILE_INSTRUMENTATION",
  "VIEW_MOBILE_SOURCE_ARTIFACTS",
  "VIEW_MOBILE_TRAFFIC",
  "MANAGE_DEVICE_LAB",
  "MANAGE_MOBILE_POLICIES",
] as const;
export type MobileSecurityPermission = (typeof MOBILE_SECURITY_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<MobileSecurityPermission, Role[]> = {
  VIEW_MOBILE_SECURITY: ALL,
  MANAGE_MOBILE_APPS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  UPLOAD_MOBILE_BUILD: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  RUN_MOBILE_STATIC_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  RUN_MOBILE_DYNAMIC_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  APPROVE_MOBILE_INSTRUMENTATION: ["OWNER", "ADMIN"],
  VIEW_MOBILE_SOURCE_ARTIFACTS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  VIEW_MOBILE_TRAFFIC: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_DEVICE_LAB: ["OWNER", "ADMIN"],
  MANAGE_MOBILE_POLICIES: ["OWNER", "ADMIN"],
};

export function hasMobileSecurityPermission(user: RequestUser, permission: MobileSecurityPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireMobileSecurityPermission(user: RequestUser, permission: MobileSecurityPermission): void {
  if (!hasMobileSecurityPermission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
