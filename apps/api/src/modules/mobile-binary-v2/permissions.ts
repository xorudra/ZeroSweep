import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Mobile & Binary Security V2 permissions (Prompt 35 §134/§135).
 * The spec's permission names are the contract; the role mapping is
 * DSRclone policy in exactly one place. §135: dynamic
 * instrumentation and debugging are SEPARATE high-risk permissions —
 * RUN_APPROVED_RUNTIME_INSTRUMENTATION is administrator-class and
 * never implied by static-analysis rights. The Prompt 17/18
 * permission sets remain in force for the V1 surfaces.
 */
export const MOBILE_BINARY_V2_PERMISSIONS = [
  "VIEW_MOBILE_SECURITY",
  "MANAGE_MOBILE_APPLICATIONS",
  "UPLOAD_MOBILE_ARTIFACT",
  "RUN_MOBILE_STATIC_ANALYSIS",
  "RUN_MOBILE_DYNAMIC_ANALYSIS",
  "MANAGE_MOBILE_TEST_DEVICES",
  "VIEW_MOBILE_EVIDENCE",
  "VIEW_MOBILE_TRAFFIC",
  "RUN_APPROVED_RUNTIME_INSTRUMENTATION",
  "VIEW_BINARY_SECURITY",
  "RUN_BINARY_ANALYSIS",
  "VIEW_DECOMPILED_EVIDENCE",
  "EXPORT_MOBILE_REPORT",
] as const;
export type MobileBinaryV2Permission = (typeof MOBILE_BINARY_V2_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const MAP: Record<MobileBinaryV2Permission, Role[]> = {
  VIEW_MOBILE_SECURITY: ALL,
  MANAGE_MOBILE_APPLICATIONS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  UPLOAD_MOBILE_ARTIFACT: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  RUN_MOBILE_STATIC_ANALYSIS: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  RUN_MOBILE_DYNAMIC_ANALYSIS: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  MANAGE_MOBILE_TEST_DEVICES: ["OWNER", "ADMIN"],
  VIEW_MOBILE_EVIDENCE: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  VIEW_MOBILE_TRAFFIC: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  // §135: separate high-risk permission — admins only.
  RUN_APPROVED_RUNTIME_INSTRUMENTATION: ["OWNER", "ADMIN"],
  VIEW_BINARY_SECURITY: ALL,
  RUN_BINARY_ANALYSIS: ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"],
  VIEW_DECOMPILED_EVIDENCE: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
  EXPORT_MOBILE_REPORT: ["OWNER", "ADMIN", "SECURITY_ENGINEER"],
};

export function hasMobileBinaryV2Permission(user: RequestUser, permission: MobileBinaryV2Permission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireMobileBinaryV2Permission(user: RequestUser, permission: MobileBinaryV2Permission): void {
  if (!hasMobileBinaryV2Permission(user, permission)) {
    throw new ForbiddenException(`Missing permission ${permission}`);
  }
}
