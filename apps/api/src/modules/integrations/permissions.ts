import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Prompt 24 §9: integration RBAC permissions. Managing secrets means
 * managing REFERENCES — no permission anywhere returns a secret value,
 * because values are never stored (§7/§8).
 */
export const INTEGRATION_PERMISSIONS = [
  "VIEW_INTEGRATIONS",
  "CREATE_INTEGRATION",
  "EDIT_INTEGRATION",
  "DELETE_INTEGRATION",
  "TEST_INTEGRATION",
  "MANAGE_INTEGRATION_SECRETS",
  "MANAGE_REPOSITORY_INTEGRATIONS",
  "MANAGE_TICKETING_INTEGRATIONS",
  "MANAGE_MESSAGING_INTEGRATIONS",
  "MANAGE_SIEM_INTEGRATIONS",
] as const;
export type IntegrationPermission = (typeof INTEGRATION_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];

export const INTEGRATION_PERMISSION_ROLES: Record<IntegrationPermission, Role[]> = {
  VIEW_INTEGRATIONS: ALL,
  CREATE_INTEGRATION: ADMINS,
  EDIT_INTEGRATION: ADMINS,
  DELETE_INTEGRATION: ADMINS,
  TEST_INTEGRATION: LEADS,
  MANAGE_INTEGRATION_SECRETS: ADMINS,
  MANAGE_REPOSITORY_INTEGRATIONS: LEADS,
  MANAGE_TICKETING_INTEGRATIONS: LEADS,
  MANAGE_MESSAGING_INTEGRATIONS: LEADS,
  MANAGE_SIEM_INTEGRATIONS: ADMINS,
};

export function hasIntegrationPermission(role: Role, permission: IntegrationPermission): boolean {
  return INTEGRATION_PERMISSION_ROLES[permission].includes(role);
}

export function requireIntegrationPermission(user: RequestUser, permission: IntegrationPermission): void {
  if (!INTEGRATION_PERMISSION_ROLES[permission].includes(user.role)) {
    throw new ForbiddenException(`Role ${user.role} lacks the ${permission} permission (Prompt 24 §9)`);
  }
}
