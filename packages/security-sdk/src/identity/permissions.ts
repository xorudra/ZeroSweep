/** Centralized permission evaluation (§10–13), authentication assurance
 *  (§37) and step-up freshness (§35). Deterministic: organization role
 *  grants a baseline, workspace role grants workspace-specific permissions,
 *  and an explicit DENY always overrides an inherited allow (§11). */

export type OrgRole = "OWNER" | "ADMIN" | "SECURITY_ADMIN" | "MEMBER" | "VIEWER";
export type WorkspaceRole = "OWNER" | "ADMIN" | "SECURITY_ADMIN" | "SECURITY_ENGINEER" | "ANALYST" | "MEMBER" | "VIEWER";

/** Baseline permission catalog granted per organization role. */
const ORG_ROLE_PERMISSIONS: Record<OrgRole, string[]> = {
  OWNER: ["org:read", "org:manage", "org:security:manage", "members:manage", "sso:manage", "scim:manage", "service-accounts:manage", "api-keys:manage", "access-reviews:manage", "workspace:read", "workspace:manage"],
  ADMIN: ["org:read", "org:manage", "members:manage", "sso:manage", "scim:manage", "service-accounts:manage", "api-keys:manage", "access-reviews:manage", "workspace:read", "workspace:manage"],
  SECURITY_ADMIN: ["org:read", "org:security:manage", "members:manage", "sso:manage", "scim:manage", "access-reviews:manage", "workspace:read"],
  MEMBER: ["org:read", "workspace:read"],
  VIEWER: ["org:read", "workspace:read"],
};

const WORKSPACE_ROLE_PERMISSIONS: Record<WorkspaceRole, string[]> = {
  OWNER: ["workspace:read", "workspace:manage", "findings:read", "findings:manage", "scans:read", "scans:create-safe", "reports:read", "assets:read"],
  ADMIN: ["workspace:read", "workspace:manage", "findings:read", "findings:manage", "scans:read", "scans:create-safe", "reports:read", "assets:read"],
  SECURITY_ADMIN: ["workspace:read", "findings:read", "findings:manage", "scans:read", "reports:read", "assets:read"],
  SECURITY_ENGINEER: ["workspace:read", "findings:read", "findings:manage", "scans:read", "scans:create-safe", "reports:read", "assets:read"],
  ANALYST: ["workspace:read", "findings:read", "scans:read", "reports:read", "assets:read"],
  MEMBER: ["workspace:read", "findings:read", "assets:read"],
  VIEWER: ["workspace:read", "findings:read", "reports:read", "assets:read"],
};

export interface PermissionInput {
  organizationRole?: OrgRole | null;
  workspaceRole?: WorkspaceRole | null;
  explicitDenies?: string[];
  resource: string; // e.g. "findings"
  action: string; // e.g. "read" | "manage"
}

export interface PermissionDecision { decision: "ALLOW" | "DENY"; reason: string }

export function evaluatePermission(input: PermissionInput): PermissionDecision {
  const permission = `${input.resource}:${input.action}`;
  if (input.explicitDenies?.includes(permission)) {
    return { decision: "DENY", reason: `Explicit deny for ${permission} overrides inherited allow` };
  }
  const orgPerms = input.organizationRole ? ORG_ROLE_PERMISSIONS[input.organizationRole] : [];
  const wsPerms = input.workspaceRole ? WORKSPACE_ROLE_PERMISSIONS[input.workspaceRole] : [];
  if (orgPerms.includes(permission)) return { decision: "ALLOW", reason: `Granted by organization role ${input.organizationRole}` };
  if (wsPerms.includes(permission)) return { decision: "ALLOW", reason: `Granted by workspace role ${input.workspaceRole}` };
  // manage implies read within the same role grant set.
  if (input.action === "read") {
    const manage = `${input.resource}:manage`;
    if (orgPerms.includes(manage) || wsPerms.includes(manage)) return { decision: "ALLOW", reason: `Granted via ${input.resource}:manage` };
  }
  return { decision: "DENY", reason: `No role grants ${permission}` };
}

export function isPrivilegedOrgRole(role: string | null | undefined): boolean {
  return role === "OWNER" || role === "ADMIN" || role === "SECURITY_ADMIN";
}

/* ------------------------- assurance & step-up --------------------------- */
export type AssuranceLevel = "AAL1" | "AAL2" | "PHISHING_RESISTANT";
export type AuthMethodKind = "PASSWORD" | "TOTP" | "RECOVERY_CODE" | "WEBAUTHN" | "PASSKEY" | "SSO" | "SSO_MFA";

/** §37 mapping of authentication methods to assurance levels. */
export function assuranceForMethods(methods: AuthMethodKind[]): AssuranceLevel {
  if (methods.includes("PASSKEY") || methods.includes("WEBAUTHN")) return "PHISHING_RESISTANT";
  if (methods.includes("TOTP") || methods.includes("SSO_MFA") || methods.includes("RECOVERY_CODE")) return "AAL2";
  return "AAL1";
}

export const STEP_UP_ACTIONS = [
  "manage SSO",
  "create API keys",
  "view raw evidence",
  "approve intrusive validation",
  "approve risk exception",
  "change organization security policy",
  "manage service accounts",
] as const;

/** Step-up is fresh for 10 minutes by default (§35). */
export function stepUpFresh(stepUpAtMs: number | null, nowMs: number, maxAgeMs = 10 * 60 * 1000): boolean {
  if (!stepUpAtMs) return false;
  return nowMs - stepUpAtMs <= maxAgeMs;
}

/** Session lifetime guard rails (§42): org settings are clamped to platform
 *  safety bounds regardless of what an admin configures. */
export function clampSessionPolicy(idleMinutes: number, absoluteMinutes: number): { idleMinutes: number; absoluteMinutes: number } {
  const idle = Math.min(Math.max(idleMinutes, 5), 24 * 60);
  const absolute = Math.min(Math.max(absoluteMinutes, idle), 7 * 24 * 60);
  return { idleMinutes: idle, absoluteMinutes: absolute };
}

export function sessionExpired(session: { createdAtMs: number; lastSeenAtMs: number; idleMinutes: number; absoluteMinutes: number; revokedAtMs: number | null }, nowMs: number): string | null {
  if (session.revokedAtMs) return "REVOKED";
  if (nowMs > session.createdAtMs + session.absoluteMinutes * 60_000) return "ABSOLUTE_TIMEOUT";
  if (nowMs > session.lastSeenAtMs + session.idleMinutes * 60_000) return "IDLE_TIMEOUT";
  return null;
}
