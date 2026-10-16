import { ForbiddenException } from "@nestjs/common";
import { PLATFORM_PERMISSIONS, type PlatformPermission } from "@dsrclone/security-sdk";
import type { RequestUser } from "../../common/decorators/auth.decorators";

export { PLATFORM_PERMISSIONS };
export type { PlatformPermission };

/**
 * Platform RBAC (Prompt 38 §201–§203, Prompt 40 §98). Platform
 * operations are deployment-level, not tenant-level: organization
 * OWNER/ADMIN/SECURITY_ADMIN roles grant NO platform-ops permission.
 * Only the deployment platform-admin flag (§96, reconciled from the
 * deployment allowlist at login via isPlatformAdminEmail in
 * @dsrclone/config) authorizes this plane — exactly like
 * ProductPermissionService.requirePlatformPermission on the product
 * plane. This covers kill switches, maintenance, backups, restores,
 * queue administration, deployment/DR records and cross-tenant
 * aggregates alike.
 */
export function hasPlatformPermission(user: RequestUser, permission: PlatformPermission): boolean {
  void permission;
  return user.isPlatformAdmin === true;
}

export function requirePlatformPermission(user: RequestUser, permission: PlatformPermission): void {
  if (!hasPlatformPermission(user, permission)) {
    throw new ForbiddenException(`platform permission ${permission} requires a platform administrator (§98/§203); organization roles do not grant platform access`);
  }
}
