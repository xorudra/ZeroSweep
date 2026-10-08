import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Web/API VAPT V2 permissions (Prompt 32 §166/§167). They layer over
 * the workspace Role like every prior phase's permission map.
 * RUN_HIGH_RISK_WEB_TESTS (§167) is deliberately ADMINS-only: HIGH
 * modules additionally need an explicit profile, active authorization
 * and a recorded approval in the plan gate (§16) — the permission
 * alone never enables them.
 */
export type WebVaptPermission =
  | "VIEW_WEB_VAPT" | "MANAGE_WEB_TARGETS" | "RUN_WEB_VAPT" | "RUN_API_VAPT"
  | "MANAGE_VAPT_PROFILES" | "MANAGE_VAPT_AUTH" | "VIEW_VAPT_EVIDENCE"
  | "CANCEL_VAPT_SCAN" | "RUN_TARGETED_VERIFICATION" | "EXPORT_VAPT_REPORT"
  | "RUN_HIGH_RISK_WEB_TESTS";

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<WebVaptPermission, Role[]> = {
  VIEW_WEB_VAPT: ALL,
  MANAGE_WEB_TARGETS: LEADS,
  RUN_WEB_VAPT: STAFF,
  RUN_API_VAPT: STAFF,
  MANAGE_VAPT_PROFILES: LEADS,
  MANAGE_VAPT_AUTH: ADMINS,
  VIEW_VAPT_EVIDENCE: LEADS,
  CANCEL_VAPT_SCAN: STAFF,
  RUN_TARGETED_VERIFICATION: LEADS,
  EXPORT_VAPT_REPORT: STAFF,
  RUN_HIGH_RISK_WEB_TESTS: ADMINS,
};

export const WEB_VAPT_PERMISSIONS = Object.keys(MAP) as WebVaptPermission[];

export function webVaptPermissionsFor(role: Role): WebVaptPermission[] {
  return WEB_VAPT_PERMISSIONS.filter((p) => MAP[p].includes(role));
}

export function requireWebVaptPermission(user: RequestUser, permission: WebVaptPermission): void {
  if (!MAP[permission].includes(user.role)) {
    throw new ForbiddenException(`Missing permission: ${permission}`);
  }
}
