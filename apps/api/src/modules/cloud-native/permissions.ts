import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Cloud-native permissions (Prompt 13 §92). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is ZeroSweep policy and lives in exactly one place.
 * Managing registry/cluster connections and runtime-event ingestion
 * are administrative; raw artifact access is OWNER/ADMIN and audited.
 */
export const CLOUD_PERMISSIONS = [
  "VIEW_CONTAINER_SECURITY",
  "RUN_CONTAINER_SCAN",
  "MANAGE_REGISTRIES",
  "VIEW_KUBERNETES",
  "RUN_KUBERNETES_SCAN",
  "MANAGE_KUBERNETES_CONNECTIONS",
  "VIEW_RUNTIME_EVENTS",
  "MANAGE_CLOUD_NATIVE_POLICIES",
  "VIEW_RAW_CLOUD_NATIVE_ARTIFACTS",
] as const;
export type CloudPermission = (typeof CLOUD_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<CloudPermission, Role[]> = {
  VIEW_CONTAINER_SECURITY: ALL,
  RUN_CONTAINER_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_REGISTRIES: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  VIEW_KUBERNETES: ALL,
  RUN_KUBERNETES_SCAN: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_KUBERNETES_CONNECTIONS: ["OWNER", "ADMIN"],
  VIEW_RUNTIME_EVENTS: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  MANAGE_CLOUD_NATIVE_POLICIES: ["OWNER", "ADMIN"],
  VIEW_RAW_CLOUD_NATIVE_ARTIFACTS: ["OWNER", "ADMIN"],
};

export function hasCloudPermission(user: RequestUser, permission: CloudPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireCloudPermission(user: RequestUser, permission: CloudPermission): void {
  if (!hasCloudPermission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
