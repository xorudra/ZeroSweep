import { ForbiddenException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * AI copilot permissions (Prompt 21 §116). They layer over the
 * workspace Role — the spec's permission names are the contract; the
 * role mapping is DSRclone policy and lives in exactly one place
 * (mirrors the Prompt 20 permissions module).
 */
export const AI_PERMISSIONS = [
  "USE_AI_COPILOT", "AI_EXPLAIN_FINDING", "AI_GENERATE_REMEDIATION", "AI_GENERATE_SECURE_CODE",
  "AI_QUERY_SECURITY_DATA", "AI_DRAFT_REPORT", "AI_PROPOSE_ACTION", "VIEW_AI_CITATIONS",
  "VIEW_AI_USAGE", "MANAGE_AI_PROVIDERS", "MANAGE_AI_POLICY",
] as const;
export type AiPermission = (typeof AI_PERMISSIONS)[number];

const ALL: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST", "VIEWER"];
const STAFF: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER", "ANALYST"];
const LEADS: Role[] = ["OWNER", "ADMIN", "SECURITY_ENGINEER"];
const ADMINS: Role[] = ["OWNER", "ADMIN"];

const MAP: Record<AiPermission, Role[]> = {
  USE_AI_COPILOT: STAFF,
  AI_EXPLAIN_FINDING: ALL,
  AI_GENERATE_REMEDIATION: STAFF,
  AI_GENERATE_SECURE_CODE: LEADS,
  AI_QUERY_SECURITY_DATA: STAFF,
  AI_DRAFT_REPORT: LEADS,
  AI_PROPOSE_ACTION: STAFF,
  VIEW_AI_CITATIONS: ALL,
  VIEW_AI_USAGE: LEADS,
  MANAGE_AI_PROVIDERS: ADMINS,
  MANAGE_AI_POLICY: ADMINS,
};

export function hasAiPermission(user: RequestUser, permission: AiPermission): boolean {
  return MAP[permission].includes(user.role);
}

export function requireAiPermission(user: RequestUser, permission: AiPermission): void {
  if (!hasAiPermission(user, permission)) {
    throw new ForbiddenException(`role ${user.role} lacks permission ${permission} (§116)`);
  }
}

/** Which §116 permission gates each copilot task (§6/§114). */
export const TASK_PERMISSION: Record<string, AiPermission> = {
  FINDING_EXPLANATION: "AI_EXPLAIN_FINDING",
  FINDING_SUMMARY: "AI_EXPLAIN_FINDING",
  EVIDENCE_SUMMARY: "AI_EXPLAIN_FINDING",
  RISK_EXPLANATION: "AI_EXPLAIN_FINDING",
  ATTACK_PATH_EXPLANATION: "AI_EXPLAIN_FINDING",
  COMPLIANCE_EXPLANATION: "AI_EXPLAIN_FINDING",
  RETEST_SUMMARY: "AI_EXPLAIN_FINDING",
  REMEDIATION_GUIDANCE: "AI_GENERATE_REMEDIATION",
  SECURE_CODE_GUIDANCE: "AI_GENERATE_SECURE_CODE",
  NATURAL_LANGUAGE_SEARCH: "AI_QUERY_SECURITY_DATA",
  SCAN_SUMMARY: "USE_AI_COPILOT",
  ASSET_SUMMARY: "USE_AI_COPILOT",
  REPORT_DRAFTING: "AI_DRAFT_REPORT",
  COPILOT_CHAT: "USE_AI_COPILOT",
};
