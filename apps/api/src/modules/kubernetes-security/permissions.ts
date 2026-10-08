import { ForbiddenException } from "@nestjs/common";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Kubernetes Security V2 permissions (Prompt 34 §139). RBAC data is
 * sensitive (it maps privilege), so VIEW_KUBERNETES_RBAC is narrower
 * than general cluster viewing; runtime security follows the SOC
 * viewing discipline.
 */
export const KUBERNETES_V2_PERMISSIONS = [
  "VIEW_KUBERNETES_SECURITY",
  "MANAGE_KUBERNETES_CLUSTERS",
  "RUN_KUBERNETES_ASSESSMENT",
  "VIEW_KUBERNETES_RBAC",
  "VIEW_RUNTIME_SECURITY",
] as const;
export type KubernetesV2Permission = (typeof KUBERNETES_V2_PERMISSIONS)[number];

type Role = RequestUser["role"];
const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<KubernetesV2Permission, Role[]> = {
  VIEW_KUBERNETES_SECURITY: ALL,
  MANAGE_KUBERNETES_CLUSTERS: ADMINS,
  RUN_KUBERNETES_ASSESSMENT: LEADS,
  VIEW_KUBERNETES_RBAC: LEADS,
  VIEW_RUNTIME_SECURITY: STAFF,
};

export function requireKubernetesV2Permission(user: RequestUser, permission: KubernetesV2Permission): void {
  if (!MAP[permission].includes(user.role)) {
    throw new ForbiddenException(`Role ${user.role} lacks ${permission} (Prompt 34 §139)`);
  }
}

export function kubernetesV2PermissionsFor(role: Role): KubernetesV2Permission[] {
  return KUBERNETES_V2_PERMISSIONS.filter((p) => MAP[p].includes(role));
}
