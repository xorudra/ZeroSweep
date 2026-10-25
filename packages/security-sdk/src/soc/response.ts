/**
 * Response action catalog + policy (Prompt 28 §74–§82).
 *
 * The catalog is CLOSED and predefined: every action is a defensive,
 * platform-internal operation with a declared permission, approval
 * mode, resource scope and rollback story. There is no generic
 * shell/script/HTTP action and none can be added through data (§76).
 * External containment (host isolation, IdP disable, …) is NOT in
 * the catalog: it requires dedicated approved connectors, and until
 * one exists those outcomes are honestly NOT_CONFIGURED.
 */

export type ResponseApprovalMode = "NO_APPROVAL" | "SINGLE_APPROVAL" | "DUAL_APPROVAL";

export interface ResponseActionDefinition {
  key: string;
  title: string;
  description: string;
  targetKind: "API_KEY" | "SESSION" | "SERVICE_ACCOUNT" | "INTEGRATION" | "AUTOMATION" | "FINDING" | "NOTIFICATION" | "CREDENTIAL" | "ASSET";
  approvalMode: ResponseApprovalMode;
  highImpact: boolean;
  rollbackAvailable: boolean;
  rollbackNote: string;
  timeoutSeconds: number;
}

export const RESPONSE_ACTION_CATALOG: readonly ResponseActionDefinition[] = [
  {
    key: "DISABLE_DSRCLONE_API_KEY", title: "Disable ZeroSweep API key",
    description: "Revoke an API key inside ZeroSweep (suspected key compromise).",
    targetKind: "API_KEY", approvalMode: "SINGLE_APPROVAL", highImpact: true,
    rollbackAvailable: true, rollbackNote: "The key can be re-enabled by an administrator; the disablement and any re-enable are audited.",
    timeoutSeconds: 60,
  },
  {
    key: "REVOKE_DSRCLONE_SESSION", title: "Revoke ZeroSweep session",
    description: "Terminate one user session inside ZeroSweep.",
    targetKind: "SESSION", approvalMode: "NO_APPROVAL", highImpact: false,
    rollbackAvailable: false, rollbackNote: "Sessions cannot be un-revoked; the user signs in again.",
    timeoutSeconds: 60,
  },
  {
    key: "DISABLE_DSRCLONE_SERVICE_ACCOUNT", title: "Disable ZeroSweep service account",
    description: "Disable a service account and its keys inside ZeroSweep.",
    targetKind: "SERVICE_ACCOUNT", approvalMode: "SINGLE_APPROVAL", highImpact: true,
    rollbackAvailable: true, rollbackNote: "The account can be re-enabled by an administrator; audited.",
    timeoutSeconds: 60,
  },
  {
    key: "PAUSE_DSRCLONE_INTEGRATION", title: "Pause ZeroSweep integration",
    description: "Pause an integration (stops its sync/delivery) inside ZeroSweep.",
    targetKind: "INTEGRATION", approvalMode: "DUAL_APPROVAL", highImpact: true,
    rollbackAvailable: true, rollbackNote: "The integration can be resumed by an administrator; audited.",
    timeoutSeconds: 60,
  },
  {
    key: "PAUSE_SCAN_AUTOMATION", title: "Pause scan automation",
    description: "Pause scheduled scan automation for the workspace.",
    targetKind: "AUTOMATION", approvalMode: "SINGLE_APPROVAL", highImpact: true,
    rollbackAvailable: true, rollbackNote: "Automation can be resumed; schedules missed while paused follow the P22 missed-run policy.",
    timeoutSeconds: 60,
  },
  {
    key: "CREATE_REMEDIATION_TICKET", title: "Create remediation ticket",
    description: "Open a remediation ticket for a linked finding through the governed integrations path.",
    targetKind: "FINDING", approvalMode: "NO_APPROVAL", highImpact: false,
    rollbackAvailable: false, rollbackNote: "Tickets are closed in the ticketing system, not deleted.",
    timeoutSeconds: 120,
  },
  {
    key: "SEND_NOTIFICATION", title: "Send notification",
    description: "Notify responders through the existing notification router.",
    targetKind: "NOTIFICATION", approvalMode: "NO_APPROVAL", highImpact: false,
    rollbackAvailable: false, rollbackNote: "Notifications cannot be unsent.",
    timeoutSeconds: 60,
  },
  {
    key: "REQUEST_CREDENTIAL_ROTATION", title: "Request credential rotation",
    description: "Create a tracked credential-rotation request for the credential owner.",
    targetKind: "CREDENTIAL", approvalMode: "NO_APPROVAL", highImpact: false,
    rollbackAvailable: false, rollbackNote: "The request can be cancelled by the owner; rotation itself happens in the owning system.",
    timeoutSeconds: 60,
  },
  {
    key: "MARK_ASSET_FOR_REVIEW", title: "Mark asset for review",
    description: "Flag an asset for analyst review in the asset inventory.",
    targetKind: "ASSET", approvalMode: "NO_APPROVAL", highImpact: false,
    rollbackAvailable: true, rollbackNote: "The flag can be cleared by an analyst.",
    timeoutSeconds: 60,
  },
] as const;

export function getResponseActionDefinition(key: string): ResponseActionDefinition | null {
  return RESPONSE_ACTION_CATALOG.find((a) => a.key === key) ?? null;
}

export function approvalsRequired(mode: ResponseApprovalMode): number {
  return mode === "NO_APPROVAL" ? 0 : mode === "SINGLE_APPROVAL" ? 1 : 2;
}

/** §126 segregation of duties + §78 approval policy evaluation. */
export function evaluateResponsePolicy(input: {
  actionKey: string;
  proposerId: string;
  approvals: Array<{ approverId: string; decision: string }>;
}): { definition: ResponseActionDefinition | null; required: number; validApprovals: number; eligible: boolean; reasons: string[] } {
  const definition = getResponseActionDefinition(input.actionKey);
  if (!definition) return { definition: null, required: 0, validApprovals: 0, eligible: false, reasons: ["ACTION_NOT_IN_CATALOG"] };
  const reasons: string[] = [];
  const seen = new Set<string>();
  let valid = 0;
  for (const a of input.approvals) {
    if (a.decision !== "APPROVED") continue;
    if (a.approverId === input.proposerId) { reasons.push("SOD_PROPOSER_CANNOT_APPROVE"); continue; }
    if (seen.has(a.approverId)) { reasons.push("DUPLICATE_APPROVER_IGNORED"); continue; }
    seen.add(a.approverId);
    valid++;
  }
  const required = approvalsRequired(definition.approvalMode);
  return { definition, required, validApprovals: valid, eligible: valid >= required, reasons };
}

/** §81: stable execution identity — a retry with the same execution
 *  ID is the same logical action and must never execute twice. */
export function responseExecutionId(incidentId: string, actionKey: string, targetReference: string, nonce: string): string {
  return `resp:${incidentId}:${actionKey}:${targetReference}:${nonce}`;
}
