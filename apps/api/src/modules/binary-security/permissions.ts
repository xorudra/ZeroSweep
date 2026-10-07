import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Binary security permissions (Prompt 18 §94). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is DSRclone policy and lives in exactly one place.
 * Raw artifact access is sensitive and audited per access (§84);
 * decompilation views are restricted (§89); debug approval is a
 * separate duty from debug request (§67 — separation of duties is
 * enforced again in the service).
 */
export const BINARY_SECURITY_PERMISSIONS = [
  "VIEW_BINARY_SECURITY",
  "UPLOAD_BINARY",
  "RUN_BINARY_STATIC_SCAN",
  "VIEW_BINARY_DECOMPILATION",
  "VIEW_BINARY_RAW_ARTIFACTS",
  "CREATE_BINARY_DIFF",
  "REQUEST_BINARY_DEBUG",
  "APPROVE_BINARY_DEBUG",
  "RUN_BINARY_DEBUG",
  "VIEW_BINARY_DEBUG_EVIDENCE",
  "MANAGE_BINARY_POLICIES",
] as const;
export type BinarySecurityPermission = (typeof BINARY_SECURITY_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<BinarySecurityPermission, Role[]> = {
  VIEW_BINARY_SECURITY: ALL,
  UPLOAD_BINARY: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  RUN_BINARY_STATIC_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_BINARY_DECOMPILATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  VIEW_BINARY_RAW_ARTIFACTS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  CREATE_BINARY_DIFF: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  REQUEST_BINARY_DEBUG: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  APPROVE_BINARY_DEBUG: ["OWNER", "ADMIN"],
  RUN_BINARY_DEBUG: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  VIEW_BINARY_DEBUG_EVIDENCE: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_BINARY_POLICIES: ["OWNER", "ADMIN"],
};

export function hasBinarySecurityPermission(user: RequestUser, permission: BinarySecurityPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireBinarySecurityPermission(user: RequestUser, permission: BinarySecurityPermission): void {
  if (!hasBinarySecurityPermission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
