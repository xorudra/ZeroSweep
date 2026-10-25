import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * SOC permissions (Prompt 28 §125). They layer over the workspace
 * Role like every prior phase's permission map. Response permissions
 * are deliberately separated — propose / approve / execute are three
 * different capabilities, and SoD is enforced in the service (§126).
 */
export type SocPermission =
  | "VIEW_SOC" | "TRIAGE_ALERTS" | "ASSIGN_ALERTS" | "MANAGE_DETECTIONS"
  | "TEST_DETECTIONS" | "ACTIVATE_DETECTIONS" | "VIEW_THREAT_INTEL" | "MANAGE_THREAT_INTEL"
  | "VIEW_INCIDENTS" | "CREATE_INCIDENTS" | "MANAGE_INCIDENTS" | "VIEW_INCIDENT_EVIDENCE"
  | "MANAGE_INCIDENT_EVIDENCE" | "PROPOSE_RESPONSE_ACTION" | "APPROVE_RESPONSE_ACTION"
  | "EXECUTE_RESPONSE_ACTION" | "MANAGE_PLAYBOOKS" | "GENERATE_INCIDENT_REPORT";

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<SocPermission, Role[]> = {
  VIEW_SOC: ALL,
  TRIAGE_ALERTS: STAFF,
  ASSIGN_ALERTS: LEADS,
  MANAGE_DETECTIONS: LEADS,
  TEST_DETECTIONS: STAFF,
  ACTIVATE_DETECTIONS: LEADS,
  VIEW_THREAT_INTEL: ALL,
  MANAGE_THREAT_INTEL: LEADS,
  VIEW_INCIDENTS: ALL,
  CREATE_INCIDENTS: STAFF,
  MANAGE_INCIDENTS: LEADS,
  VIEW_INCIDENT_EVIDENCE: LEADS,
  MANAGE_INCIDENT_EVIDENCE: LEADS,
  PROPOSE_RESPONSE_ACTION: STAFF,
  APPROVE_RESPONSE_ACTION: LEADS,
  EXECUTE_RESPONSE_ACTION: LEADS,
  MANAGE_PLAYBOOKS: LEADS,
  GENERATE_INCIDENT_REPORT: STAFF,
};

export function hasSocPermission(user: RequestUser, permission: SocPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireSocPermission(user: RequestUser, permission: SocPermission): void {
  if (!hasSocPermission(user, permission)) {
    throw new ForbiddenException(`Missing SOC permission: ${permission}`);
  }
}

export function socPermissionsFor(user: RequestUser): SocPermission[] {
  return (Object.keys(MAP) as SocPermission[]).filter((p) => hasSocPermission(user, p));
}
