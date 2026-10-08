import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Continuous-security permissions (Prompt 22 §87). They layer over
 * the workspace Role — the spec's permission names are the contract;
 * the role mapping is DSRclone policy and lives in exactly one place
 * (mirrors the Prompt 20/21 permissions modules).
 */
export const CONTINUOUS_PERMISSIONS = [
  "VIEW_CONTINUOUS_SECURITY", "MANAGE_MONITORING_POLICIES", "MANAGE_SCAN_SCHEDULES",
  "RUN_SCHEDULE_NOW", "VIEW_SECURITY_DRIFT", "VIEW_POSTURE_HISTORY",
  "MANAGE_AUTOMATION_WORKFLOWS", "MANAGE_NOTIFICATION_POLICIES", "VIEW_AUTOMATION_EXECUTIONS",
] as const;
export type ContinuousPermission = (typeof CONTINUOUS_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<ContinuousPermission, Role[]> = {
  VIEW_CONTINUOUS_SECURITY: ALL,
  MANAGE_MONITORING_POLICIES: LEADS,
  MANAGE_SCAN_SCHEDULES: LEADS,
  RUN_SCHEDULE_NOW: LEADS,
  VIEW_SECURITY_DRIFT: ALL,
  VIEW_POSTURE_HISTORY: ALL,
  MANAGE_AUTOMATION_WORKFLOWS: LEADS,
  MANAGE_NOTIFICATION_POLICIES: ADMINS,
  VIEW_AUTOMATION_EXECUTIONS: STAFF,
};

export function hasContinuousPermission(user: RequestUser, permission: ContinuousPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireContinuousPermission(user: RequestUser, permission: ContinuousPermission): void {
  if (!hasContinuousPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§87)`);
  }
}
