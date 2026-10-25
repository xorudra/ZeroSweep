import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Remediation orchestration permissions (Prompt 31 §121). They layer
 * over the workspace Role — the spec's permission names are the
 * contract; the role mapping is ZeroSweep policy in exactly one place.
 */
export const REMEDIATION_PERMISSIONS = [
  "VIEW_REMEDIATION",
  "TRIAGE_FINDINGS",
  "ASSIGN_REMEDIATION",
  "MANAGE_REMEDIATION_PLAN",
  "CREATE_REMEDIATION_TICKET",
  "CLAIM_FIX",
  "REQUEST_VERIFICATION",
  "PERFORM_MANUAL_VERIFICATION",
  "CLOSE_VERIFIED_FINDING",
  "MANAGE_REMEDIATION_SLA",
  "PAUSE_REMEDIATION_SLA",
  "MANAGE_REMEDIATION_EXCEPTION",
  "APPROVE_REMEDIATION_EXCEPTION",
  "MANAGE_REMEDIATION_CAMPAIGN",
] as const;
export type RemediationPermission = (typeof REMEDIATION_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<RemediationPermission, Role[]> = {
  VIEW_REMEDIATION: ALL,
  TRIAGE_FINDINGS: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  ASSIGN_REMEDIATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_REMEDIATION_PLAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  CREATE_REMEDIATION_TICKET: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  CLAIM_FIX: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  REQUEST_VERIFICATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  PERFORM_MANUAL_VERIFICATION: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  CLOSE_VERIFIED_FINDING: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_REMEDIATION_SLA: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  PAUSE_REMEDIATION_SLA: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_REMEDIATION_EXCEPTION: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  APPROVE_REMEDIATION_EXCEPTION: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_REMEDIATION_CAMPAIGN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
};

export function hasRemediationPermission(user: RequestUser, permission: RemediationPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireRemediationPermission(user: RequestUser, permission: RemediationPermission): void {
  if (!hasRemediationPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§121)`);
  }
}
