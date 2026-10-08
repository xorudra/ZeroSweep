import { ForbiddenException } from "@nestjs/common";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Network VAPT V2 permissions (Prompt 33 §129/§130) mapped onto the
 * platform role lattice, following the Prompt 32 discipline. The
 * sensitive capabilities are deliberately narrow: high-throughput
 * scanning and controlled Metasploit verification are ADMIN-only, and
 * Metasploit verification is its OWN permission (§130) — holding every
 * other network permission does not imply it.
 */
export const NETWORK_PERMISSIONS = [
  "VIEW_NETWORK_VAPT", "MANAGE_NETWORK_TARGETS", "RUN_NETWORK_DISCOVERY",
  "RUN_NETWORK_VAPT", "RUN_NETWORK_VULNERABILITY_SCAN", "RUN_HIGH_THROUGHPUT_PORT_SCAN",
  "RUN_CREDENTIALLED_NETWORK_SCAN", "RUN_TARGETED_NETWORK_VERIFICATION",
  "VIEW_NETWORK_EVIDENCE", "CREATE_PACKET_CAPTURE", "VIEW_PACKET_CAPTURE",
  "MANAGE_NETWORK_PROFILES", "EXPORT_NETWORK_REPORT", "RUN_CONTROLLED_METASPLOIT_VERIFICATION",
] as const;
export type NetworkPermission = (typeof NETWORK_PERMISSIONS)[number];

type Role = RequestUser["role"];
const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<NetworkPermission, Role[]> = {
  VIEW_NETWORK_VAPT: ALL,
  MANAGE_NETWORK_TARGETS: LEADS,
  RUN_NETWORK_DISCOVERY: STAFF,
  RUN_NETWORK_VAPT: STAFF,
  RUN_NETWORK_VULNERABILITY_SCAN: LEADS,
  RUN_HIGH_THROUGHPUT_PORT_SCAN: ADMINS,
  RUN_CREDENTIALLED_NETWORK_SCAN: ADMINS,
  RUN_TARGETED_NETWORK_VERIFICATION: LEADS,
  VIEW_NETWORK_EVIDENCE: LEADS,
  CREATE_PACKET_CAPTURE: LEADS,
  VIEW_PACKET_CAPTURE: LEADS,
  MANAGE_NETWORK_PROFILES: LEADS,
  EXPORT_NETWORK_REPORT: STAFF,
  RUN_CONTROLLED_METASPLOIT_VERIFICATION: ADMINS,
};

export function requireNetworkPermission(user: RequestUser, permission: NetworkPermission): void {
  if (!MAP[permission].includes(user.role)) {
    throw new ForbiddenException(`Role ${user.role} lacks ${permission} (Prompt 33 §129)`);
  }
}

export function networkPermissionsFor(role: Role): NetworkPermission[] {
  return NETWORK_PERMISSIONS.filter((p) => MAP[p].includes(role));
}
