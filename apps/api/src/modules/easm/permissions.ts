import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * EASM permissions (Prompt 29 §117). They layer over the workspace
 * Role like every prior phase's permission map. §118 segregation is
 * deliberate: VERIFY_ASSET_OWNERSHIP (proving an asset is ours) and
 * AUTHORIZE_EASM_ACTIVE_TESTING (allowing active probing of it) are
 * DIFFERENT capabilities held to different role sets, so holding one
 * never implies the other.
 */
export type EasmPermission =
  | "VIEW_EASM" | "MANAGE_EASM" | "MANAGE_EASM_SCOPE" | "VERIFY_ASSET_OWNERSHIP"
  | "AUTHORIZE_EASM_ACTIVE_TESTING" | "RUN_EASM_DISCOVERY" | "VIEW_EASM_EVIDENCE"
  | "MANAGE_ASSET_OWNERS" | "ACKNOWLEDGE_EASM_DRIFT" | "EXPORT_EASM";

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<EasmPermission, Role[]> = {
  VIEW_EASM: ALL,
  MANAGE_EASM: LEADS,
  MANAGE_EASM_SCOPE: ADMINS,
  VERIFY_ASSET_OWNERSHIP: LEADS,
  AUTHORIZE_EASM_ACTIVE_TESTING: ADMINS,
  RUN_EASM_DISCOVERY: STAFF,
  VIEW_EASM_EVIDENCE: LEADS,
  MANAGE_ASSET_OWNERS: LEADS,
  ACKNOWLEDGE_EASM_DRIFT: STAFF,
  EXPORT_EASM: STAFF,
};

export function hasEasmPermission(user: RequestUser, permission: EasmPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireEasmPermission(user: RequestUser, permission: EasmPermission): void {
  if (!hasEasmPermission(user, permission)) {
    throw new ForbiddenException(`Missing EASM permission: ${permission}`);
  }
}

export function easmPermissionsFor(user: RequestUser): EasmPermission[] {
  return (Object.keys(MAP) as EasmPermission[]).filter((p) => hasEasmPermission(user, p));
}
