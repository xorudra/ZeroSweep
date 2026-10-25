import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import { GRC_PERMISSIONS, type GrcPermission } from "@zerosweep/security-sdk";
import type { RequestUser } from "../../common/decorators/auth.decorators";

export { GRC_PERMISSIONS };
export type { GrcPermission };

/**
 * GRC permissions (Prompt 26 §110). They layer over the workspace Role —
 * the spec's permission names are the contract; the role mapping is
 * ZeroSweep policy and lives in exactly one place (mirrors the Prompt
 * 20–24 permissions modules). Restricted evidence (§41) is leads-only;
 * time-limited auditor access (§74/§75) is grant-based and checked in
 * the services, not here.
 */
const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<GrcPermission, Role[]> = {
  VIEW_GRC: ALL,
  MANAGE_FRAMEWORKS: ADMINS,
  VIEW_CONTROLS: ALL,
  MANAGE_CONTROLS: LEADS,
  TEST_CONTROLS: LEADS,
  VIEW_COMPLIANCE_EVIDENCE: STAFF,
  UPLOAD_COMPLIANCE_EVIDENCE: STAFF,
  VIEW_RESTRICTED_EVIDENCE: LEADS,
  MANAGE_ASSESSMENTS: LEADS,
  REVIEW_ASSESSMENTS: ADMINS,
  VIEW_RISK_REGISTER: ALL,
  MANAGE_RISKS: STAFF,
  APPROVE_RISK_ACCEPTANCE: ADMINS,
  MANAGE_POLICIES: ADMINS,
  VIEW_AUDITS: STAFF,
  MANAGE_AUDITS: LEADS,
  REVIEW_AUDIT_EVIDENCE: LEADS,
  GENERATE_AUDIT_PACKAGE: ADMINS,
  MANAGE_VENDOR_RISK: LEADS,
};

export function hasGrcPermission(user: RequestUser, permission: GrcPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireGrcPermission(user: RequestUser, permission: GrcPermission): void {
  if (!hasGrcPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§110)`);
  }
}
