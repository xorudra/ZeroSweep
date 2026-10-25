import { ForbiddenException, Inject, Injectable } from "@nestjs/common";
import {
  PLATFORM_PRODUCT_PERMISSIONS, hasBillingPermission,
  type BillingPermission, type PlatformProductPermission,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";

export { PLATFORM_PRODUCT_PERMISSIONS };
export type { BillingPermission, PlatformProductPermission };

/**
 * Product RBAC (Prompt 40 §98/§135/§136).
 *
 * Tenant billing permissions layer over organization roles (§135).
 * Platform permissions require the deployment-level platform-admin
 * flag on the user record (§96/§98) — an organization OWNER without
 * the flag is NOT a platform admin, and platform routes never serve
 * tenant data beyond safe metadata (§104–§106).
 */
@Injectable()
export class ProductPermissionService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async isPlatformAdmin(user: RequestUser): Promise<boolean> {
    const row = await (this.prisma as any).user.findUnique({ where: { id: user.id }, select: { isPlatformAdmin: true } });
    return Boolean(row?.isPlatformAdmin);
  }

  /** All §136 permissions are granted by the platform-admin flag in v1.0. */
  async requirePlatformPermission(user: RequestUser, permission: PlatformProductPermission): Promise<void> {
    if (!(await this.isPlatformAdmin(user))) {
      throw new ForbiddenException(`Platform permission ${permission} requires a platform administrator (§98/§136). Organization roles do not grant platform access.`);
    }
  }

  requireBillingPermission(user: RequestUser, permission: BillingPermission): void {
    if (!hasBillingPermission(user.role, permission)) {
      throw new ForbiddenException(`Role ${user.role} lacks billing permission ${permission} (§135).`);
    }
  }
}
