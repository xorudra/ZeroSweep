import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Wireless security permissions (Prompt 19 §79). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is ZeroSweep policy and lives in exactly one place.
 * Raw capture access is sensitive and audited per access (§30);
 * station raw addresses are never exposed by ordinary views (§90);
 * lab-validation approval is a separate duty from requesting (§65).
 */
export const WIRELESS_SECURITY_PERMISSIONS = [
  "VIEW_WIRELESS_SECURITY",
  "MANAGE_WIRELESS_ENVIRONMENTS",
  "MANAGE_WIRELESS_SENSORS",
  "RUN_PASSIVE_WIRELESS_SCAN",
  "UPLOAD_WIRELESS_CAPTURE",
  "VIEW_RAW_WIRELESS_CAPTURES",
  "MANAGE_APPROVED_APS",
  "VIEW_WIRELESS_EVENTS",
  "MANAGE_WIRELESS_POLICIES",
  "REQUEST_WIRELESS_LAB_VALIDATION",
  "APPROVE_WIRELESS_LAB_VALIDATION",
] as const;
export type WirelessSecurityPermission = (typeof WIRELESS_SECURITY_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<WirelessSecurityPermission, Role[]> = {
  VIEW_WIRELESS_SECURITY: ALL,
  MANAGE_WIRELESS_ENVIRONMENTS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_WIRELESS_SENSORS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  RUN_PASSIVE_WIRELESS_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  UPLOAD_WIRELESS_CAPTURE: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_RAW_WIRELESS_CAPTURES: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_APPROVED_APS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  VIEW_WIRELESS_EVENTS: ALL,
  MANAGE_WIRELESS_POLICIES: ["OWNER", "ADMIN"],
  REQUEST_WIRELESS_LAB_VALIDATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  APPROVE_WIRELESS_LAB_VALIDATION: ["OWNER", "ADMIN"],
};

export function hasWirelessSecurityPermission(user: RequestUser, permission: WirelessSecurityPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireWirelessSecurityPermission(user: RequestUser, permission: WirelessSecurityPermission): void {
  if (!hasWirelessSecurityPermission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
