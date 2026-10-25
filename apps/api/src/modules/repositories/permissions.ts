import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Source-security permissions (Prompt 12 §98). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is ZeroSweep policy and lives in exactly one place. Raw
 * source artifact access is the strongest permission in the module
 * (OWNER/ADMIN only) and is always audited (§98/§110).
 */
export const SOURCE_PERMISSIONS = [
  "VIEW_SOURCE_REPOSITORIES",
  "MANAGE_SOURCE_REPOSITORIES",
  "RUN_SOURCE_SCAN",
  "VIEW_CODE_FINDINGS",
  "VIEW_SECRET_METADATA",
  "VIEW_RAW_SOURCE_ARTIFACTS",
  "MANAGE_SOURCE_POLICIES",
  "EXPORT_SBOM",
] as const;
export type SourcePermission = (typeof SOURCE_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<SourcePermission, Role[]> = {
  VIEW_SOURCE_REPOSITORIES: ALL,
  MANAGE_SOURCE_REPOSITORIES: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  RUN_SOURCE_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_CODE_FINDINGS: ALL,
  VIEW_SECRET_METADATA: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_RAW_SOURCE_ARTIFACTS: ["OWNER", "ADMIN"],
  MANAGE_SOURCE_POLICIES: ["OWNER", "ADMIN"],
  EXPORT_SBOM: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
};

export function hasSourcePermission(user: RequestUser, permission: SourcePermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireSourcePermission(user: RequestUser, permission: SourcePermission): void {
  if (!hasSourcePermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§98)`);
  }
}
