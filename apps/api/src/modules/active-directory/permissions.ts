import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Active Directory permissions (Prompt 15 §101). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is ZeroSweep policy and lives in exactly one place.
 * Raw directory graph / artifact access is OWNER/ADMIN and audited
 * per access (§30); managing connections is administrative.
 */
export const AD_SECURITY_PERMISSIONS = [
  "VIEW_AD_SECURITY",
  "MANAGE_AD_CONNECTIONS",
  "RUN_AD_SCAN",
  "VIEW_AD_IDENTITIES",
  "VIEW_AD_GRAPH",
  "VIEW_AD_ATTACK_PATHS",
  "VIEW_ADCS",
  "VIEW_AD_RAW_ARTIFACTS",
  "MANAGE_AD_POLICIES",
  "VIEW_RAW_DIRECTORY_GRAPH",
] as const;
export type AdSecurityPermission = (typeof AD_SECURITY_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<AdSecurityPermission, Role[]> = {
  VIEW_AD_SECURITY: ALL,
  MANAGE_AD_CONNECTIONS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  RUN_AD_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_AD_IDENTITIES: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_AD_GRAPH: ALL,
  VIEW_AD_ATTACK_PATHS: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_ADCS: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_AD_RAW_ARTIFACTS: ["OWNER", "ADMIN"],
  MANAGE_AD_POLICIES: ["OWNER", "ADMIN"],
  VIEW_RAW_DIRECTORY_GRAPH: ["OWNER", "ADMIN"],
};

export function hasAdSecurityPermission(user: RequestUser, permission: AdSecurityPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireAdSecurityPermission(user: RequestUser, permission: AdSecurityPermission): void {
  if (!hasAdSecurityPermission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
