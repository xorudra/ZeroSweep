/**
 * Product RBAC permissions and audit actions (Prompt 40 §135–§137).
 *
 * Tenant billing permissions (§135) layer over organization roles.
 * Platform permissions (§136) require the deployment-level platform
 * admin flag — organization OWNER/ADMIN alone never grants them (§98).
 * Tenants can never modify their own entitlements or billable usage
 * (§140/§298); quota overrides are platform-issued (§138).
 */

export const BILLING_PERMISSIONS = [
  "VIEW_BILLING",
  "MANAGE_BILLING",
  "VIEW_USAGE",
  "MANAGE_PLAN",
  "MANAGE_LICENSE",
] as const;
export type BillingPermission = (typeof BILLING_PERMISSIONS)[number];

export const PLATFORM_PRODUCT_PERMISSIONS = [
  "VIEW_PLATFORM_ORGANIZATIONS",
  "MANAGE_PLATFORM_ORGANIZATIONS",
  "VIEW_PLATFORM_SUBSCRIPTIONS",
  "MANAGE_PLATFORM_SUBSCRIPTIONS",
  "VIEW_PLATFORM_USAGE",
  "MANAGE_PLATFORM_LICENSES",
  "MANAGE_PRODUCT_PLANS",
  "MANAGE_PRODUCT_FEATURES",
  "MANAGE_SUPPORT_ACCESS",
] as const;
export type PlatformProductPermission = (typeof PLATFORM_PRODUCT_PERMISSIONS)[number];

/** Organization roles allowed each tenant billing permission (§135). */
export const BILLING_PERMISSION_ROLES: Record<BillingPermission, string[]> = {
  VIEW_BILLING: ["OWNER", "ADMIN"],
  MANAGE_BILLING: ["OWNER"],
  VIEW_USAGE: ["OWNER", "ADMIN", "SECURITY_ADMIN", "SECURITY_ENGINEER", "ANALYST", "MEMBER", "VIEWER"],
  MANAGE_PLAN: ["OWNER"],
  MANAGE_LICENSE: ["OWNER", "ADMIN"],
};

export function hasBillingPermission(role: string, permission: BillingPermission): boolean {
  return BILLING_PERMISSION_ROLES[permission]?.includes(role) ?? false;
}

/** §137 product audit actions (added to the AuditAction enum in the DB). */
export const PRODUCT_AUDIT_ACTIONS = [
  "PLAN_CREATED",
  "PLAN_UPDATED",
  "PLAN_ACTIVATED",
  "SUBSCRIPTION_CREATED",
  "SUBSCRIPTION_UPDATED",
  "SUBSCRIPTION_CANCELLED",
  "TRIAL_STARTED",
  "TRIAL_EXPIRED",
  "LICENSE_INSTALLED",
  "LICENSE_REJECTED",
  "LICENSE_EXPIRED",
  "QUOTA_EXCEEDED",
  "QUOTA_OVERRIDE_CREATED",
  "BILLING_WEBHOOK_RECEIVED",
  "BILLING_WEBHOOK_REJECTED",
  "ORGANIZATION_PROVISIONED",
  "ORGANIZATION_SUSPENDED",
  "ORGANIZATION_REACTIVATED",
  "ORGANIZATION_CANCELLATION_REQUESTED",
  "ORGANIZATION_DELETION_REQUESTED",
  "SUPPORT_ACCESS_STARTED",
  "SUPPORT_ACCESS_ENDED",
] as const;
export type ProductAuditAction = (typeof PRODUCT_AUDIT_ACTIONS)[number];
