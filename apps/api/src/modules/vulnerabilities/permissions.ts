import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Vulnerability-management permissions (Prompt 11 §78). They layer over
 * the workspace Role — the spec's permission names are the contract;
 * the role mapping is DSRclone policy and lives in exactly one place.
 */
export const VM_PERMISSIONS = [
  "VIEW_VULNERABILITIES",
  "TRIAGE_VULNERABILITIES",
  "ASSIGN_VULNERABILITIES",
  "ACCEPT_RISK",
  "MARK_FALSE_POSITIVE",
  "REQUEST_RETEST",
  "MANAGE_SCANNERS",
  "VIEW_RAW_SCANNER_ARTIFACTS",
] as const;
export type VmPermission = (typeof VM_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<VmPermission, Role[]> = {
  VIEW_VULNERABILITIES: ALL,
  TRIAGE_VULNERABILITIES: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  ASSIGN_VULNERABILITIES: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  ACCEPT_RISK: ["OWNER", "ADMIN"],
  MARK_FALSE_POSITIVE: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  REQUEST_RETEST: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_SCANNERS: ["OWNER", "ADMIN"],
  VIEW_RAW_SCANNER_ARTIFACTS: ["OWNER", "ADMIN"],
};

export function hasVmPermission(user: RequestUser, permission: VmPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireVmPermission(user: RequestUser, permission: VmPermission): void {
  if (!hasVmPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§78)`);
  }
}
