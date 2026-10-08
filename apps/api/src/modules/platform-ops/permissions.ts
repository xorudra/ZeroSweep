import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import { PLATFORM_PERMISSIONS, type PlatformPermission } from "@dsrclone/security-sdk";
import type { RequestUser } from "../../common/decorators/auth.decorators";

export { PLATFORM_PERMISSIONS };
export type { PlatformPermission };

/**
 * Platform RBAC (Prompt 38 §201–§203). Platform operations are
 * deployment-level, not tenant-level: they layer over the organization
 * OWNER/ADMIN roles, with SECURITY_ADMIN read-only on health/metrics.
 * RUN_RESTORE is OWNER-only — restores are the most dangerous operation
 * on the plane and additionally require the typed confirmation (§202).
 */
const VIEWERS: Role[] = ["OWNER", "ADMIN", "SECURITY_ADMIN"];
const OPERATORS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<PlatformPermission, Role[]> = {
  VIEW_PLATFORM_HEALTH: VIEWERS,
  VIEW_PLATFORM_METRICS: VIEWERS,
  MANAGE_QUEUES: OPERATORS,
  MANAGE_WORKERS: OPERATORS,
  MANAGE_PLATFORM_CONFIG: OPERATORS,
  MANAGE_BACKUPS: OPERATORS,
  RUN_RESTORE: ["OWNER"],
  MANAGE_MAINTENANCE: OPERATORS,
  MANAGE_DEPLOYMENTS: OPERATORS,
};

export function hasPlatformPermission(user: RequestUser, permission: PlatformPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requirePlatformPermission(user: RequestUser, permission: PlatformPermission): void {
  if (!hasPlatformPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks platform permission ${permission} (§203)`);
  }
}
