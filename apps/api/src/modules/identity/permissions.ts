import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/** Identity permissions (Prompt 23). Layered over the organization Role;
 *  the mapping lives in exactly one place. Tenant isolation is enforced by
 *  scoping every query to the caller's organizationId — never by the UI. */
export const IDENTITY_PERMISSIONS = [
  "VIEW_MEMBERS", "MANAGE_MEMBERS", "MANAGE_SSO", "MANAGE_SCIM",
  "MANAGE_SERVICE_ACCOUNTS", "MANAGE_API_KEYS", "MANAGE_SECURITY_POLICY",
  "MANAGE_ACCESS_REVIEWS", "VIEW_PRIVILEGED_REPORT", "MANAGE_DOMAINS",
  "MANAGE_INVITATIONS", "MANAGE_BREAK_GLASS",
] as const;
export type IdentityPermission = (typeof IDENTITY_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ADMIN", "SECURITY_ENGINEER", "MEMBER", "ANALYST", "VIEWER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];
const SECURITY: Role[] = ["OWNER", "ADMIN", "SECURITY_ADMIN"];
const MAP: Record<IdentityPermission, Role[]> = {
  VIEW_MEMBERS: ALL,
  MANAGE_MEMBERS: [...ADMINS, "SECURITY_ADMIN"],
  MANAGE_SSO: SECURITY,
  MANAGE_SCIM: SECURITY,
  MANAGE_SERVICE_ACCOUNTS: SECURITY,
  MANAGE_API_KEYS: ALL, // personal keys; service-account keys additionally gated in service
  MANAGE_SECURITY_POLICY: SECURITY,
  MANAGE_ACCESS_REVIEWS: SECURITY,
  VIEW_PRIVILEGED_REPORT: SECURITY,
  MANAGE_DOMAINS: ADMINS,
  MANAGE_INVITATIONS: [...ADMINS, "SECURITY_ADMIN"],
  MANAGE_BREAK_GLASS: ADMINS,
};

export function requireIdentityPermission(user: RequestUser, permission: IdentityPermission): void {
  if (!MAP[permission].includes(user.role)) {
    throw new ForbiddenException(`Missing identity permission ${permission}`);
  }
}
