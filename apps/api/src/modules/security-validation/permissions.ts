import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Security-validation permissions (Prompt 16 §62). Same pattern as the
 * Prompt 11 VM permissions: the spec's permission names are the
 * contract; the role mapping is DSRclone policy in exactly one place.
 * USE_INTRUSIVE_VALIDATION exists as a permission so the §63
 * architecture can name it — no role is granted automated intrusive
 * execution by default, and the engine has no intrusive validator.
 */
export const VALIDATION_PERMISSIONS = [
  "REQUEST_SECURITY_VALIDATION",
  "APPROVE_SECURITY_VALIDATION",
  "RUN_SAFE_VALIDATION",
  "CANCEL_VALIDATION",
  "VIEW_VALIDATION_EVIDENCE",
  "ADD_MANUAL_VALIDATION",
  "MANAGE_VALIDATION_POLICY",
  "USE_INTRUSIVE_VALIDATION",
] as const;
export type ValidationPermission = (typeof VALIDATION_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<ValidationPermission, Role[]> = {
  REQUEST_SECURITY_VALIDATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  APPROVE_SECURITY_VALIDATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  RUN_SAFE_VALIDATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  CANCEL_VALIDATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_VALIDATION_EVIDENCE: ALL,
  ADD_MANUAL_VALIDATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_VALIDATION_POLICY: ["OWNER", "ADMIN"],
  USE_INTRUSIVE_VALIDATION: ["OWNER"],
};

export function hasValidationPermission(user: RequestUser, permission: ValidationPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireValidationPermission(user: RequestUser, permission: ValidationPermission): void {
  if (!hasValidationPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§62)`);
  }
}
