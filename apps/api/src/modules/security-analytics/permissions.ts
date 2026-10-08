import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Analytics permissions (Prompt 27 §23/§24/§110). They layer over the
 * workspace Role, mirroring the Prompt 20–26 permissions modules.
 * The classification ceiling is part of the security context: it is
 * enforced in the search WHERE clause (before retrieval) and baked
 * into every cache key (§122).
 */
export type AnalyticsPermission =
  | "VIEW_ANALYTICS" | "SEARCH_SECURITY" | "EXPORT_ANALYTICS"
  | "VIEW_ATTACK_PATHS" | "MANAGE_ANALYTICS" | "VIEW_RESTRICTED_ANALYTICS";

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<AnalyticsPermission, Role[]> = {
  VIEW_ANALYTICS: ALL,
  SEARCH_SECURITY: ALL,
  EXPORT_ANALYTICS: STAFF,
  VIEW_ATTACK_PATHS: STAFF,
  MANAGE_ANALYTICS: ADMINS,
  VIEW_RESTRICTED_ANALYTICS: LEADS,
};

export function hasAnalyticsPermission(user: RequestUser, permission: AnalyticsPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireAnalyticsPermission(user: RequestUser, permission: AnalyticsPermission): void {
  if (!hasAnalyticsPermission(user, permission)) {
    throw new ForbiddenException(`Missing analytics permission: ${permission}`);
  }
}

export function permissionsFor(user: RequestUser): AnalyticsPermission[] {
  return (Object.keys(MAP) as AnalyticsPermission[]).filter((p) => hasAnalyticsPermission(user, p));
}

/** §24: highest classification the caller may retrieve. */
export function classificationCeiling(user: RequestUser): string {
  return hasAnalyticsPermission(user, "VIEW_RESTRICTED_ANALYTICS") ? "RESTRICTED" : "CONFIDENTIAL";
}

export const CLASSIFICATION_ORDER = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;

export function allowedClassifications(user: RequestUser): string[] {
  const ceiling = classificationCeiling(user);
  return CLASSIFICATION_ORDER.slice(0, CLASSIFICATION_ORDER.indexOf(ceiling as never) + 1) as unknown as string[];
}
