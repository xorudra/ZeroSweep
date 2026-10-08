import { ForbiddenException } from "@nestjs/common";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Container Security V2 permissions (Prompt 34 §139). Registry
 * management is administrative; scanning is a lead capability; SBOM
 * viewing follows least privilege (SBOMs reveal dependency detail).
 */
export const CONTAINER_V2_PERMISSIONS = [
  "VIEW_CONTAINER_SECURITY",
  "MANAGE_CONTAINER_REGISTRIES",
  "RUN_CONTAINER_SCAN",
  "RUN_CONTAINER_ASSESSMENT",
  "VIEW_SBOM",
] as const;
export type ContainerV2Permission = (typeof CONTAINER_V2_PERMISSIONS)[number];

type Role = RequestUser["role"];
const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<ContainerV2Permission, Role[]> = {
  VIEW_CONTAINER_SECURITY: ALL,
  MANAGE_CONTAINER_REGISTRIES: ADMINS,
  RUN_CONTAINER_SCAN: LEADS,
  RUN_CONTAINER_ASSESSMENT: LEADS,
  VIEW_SBOM: STAFF,
};

export function requireContainerV2Permission(user: RequestUser, permission: ContainerV2Permission): void {
  if (!MAP[permission].includes(user.role)) {
    throw new ForbiddenException(`Role ${user.role} lacks ${permission} (Prompt 34 §139)`);
  }
}

export function containerV2PermissionsFor(role: Role): ContainerV2Permission[] {
  return CONTAINER_V2_PERMISSIONS.filter((p) => MAP[p].includes(role));
}
