import { scrubSecretPatterns, sanitizeUntrustedText } from "./sanitize";
import type { SanitizedFindingView } from "./types";

/**
 * Jira ticket payloads + bidirectional status synchronization
 * (Prompt 24 §46–§54, §124–§126).
 *
 * §52 is absolute: a CLOSED ticket is NOT a resolved finding. The
 * ticket's mapped status lives on the TICKET; the finding lifecycle
 * changes only through the platform's evidence/retest policy. The
 * sync engine below therefore never emits a "resolve the finding"
 * instruction — it reports the mapped ticket status and conflicts.
 */

/** §51: external Jira statuses map onto the ticket status vocabulary. */
export type TicketStatus = "OPEN" | "IN_PROGRESS" | "RESOLVED" | "CLOSED";

export function mapJiraStatusToInternal(input: { statusName?: string; statusCategory?: string }): TicketStatus {
  const name = (input.statusName ?? "").toLowerCase();
  if (name === "closed" || name === "done" || name === "cancelled" || name === "canceled") return "CLOSED";
  if (input.statusCategory === "done") return "RESOLVED";
  if (input.statusCategory === "indeterminate") return "IN_PROGRESS";
  if (name.includes("progress") || name.includes("review") || name.includes("testing")) return "IN_PROGRESS";
  if (name.includes("resolved") || name.includes("fixed")) return "RESOLVED";
  return "OPEN";
}

/** §50: the sanitized ticket template. Finding fields pass through
 *  the secret scrubber; a raw secret value can never reach Jira. */
export function buildJiraIssuePayload(
  finding: SanitizedFindingView,
  mapping: { projectKey: string; issueType: string },
): { payload: Record<string, unknown>; redactions: string[] } {
  const redactions: string[] = [];
  const clean = (text: string | undefined, max = 1000): string => {
    if (!text) return "";
    const { text: scrubbed, redactions: r } = scrubSecretPatterns(sanitizeUntrustedText(text, max));
    redactions.push(...r);
    return scrubbed;
  };
  const summary = clean(`[${finding.severity}] ${finding.title}`, 255);
  const location = finding.filePath
    ? `${finding.filePath}${finding.startLine ? `:${finding.startLine}` : ""}`
    : (finding.assetReference ?? "n/a");
  const description = [
    `Security finding from ZeroSweep: ${finding.dsrcloneReference}`,
    `Severity: ${finding.severity}${finding.priority ? ` · Priority: ${finding.priority}` : ""}`,
    `Status: ${finding.lifecycleStatus} · Verification: ${finding.verificationStatus}${finding.kevListed ? " · KEV-listed" : ""}`,
    `Affected asset: ${location}`,
    finding.riskExplanation ? `\nRisk:\n${clean(finding.riskExplanation)}` : "",
    finding.remediation ? `\nRemediation:\n${clean(finding.remediation)}` : "",
    "\nResolution in ZeroSweep requires evidence/retest — closing this ticket does not close the finding.",
  ].filter(Boolean).join("\n");
  return {
    payload: {
      fields: {
        project: { key: mapping.projectKey },
        issuetype: { name: mapping.issueType },
        summary,
        description,
        labels: ["dsrclone", "security", `severity-${finding.severity.toLowerCase()}`],
      },
    },
    redactions,
  };
}

export interface TicketSyncSide {
  status: string;
  assigneeReference?: string | null;
}

export interface TicketConflict {
  field: "status" | "assignee";
  localValue: string | null;
  externalValue: string | null;
}

/**
 * §53/§54/§126: three-way comparison against the last-synced
 * snapshot. A field conflicts only when BOTH sides moved away from
 * the snapshot in different directions — one-sided changes sync
 * cleanly. Conflicts are returned for an analyst decision; this
 * function never picks a winner.
 */
export function detectTicketConflicts(input: {
  local: TicketSyncSide;
  external: TicketSyncSide;
  lastSynced: TicketSyncSide;
}): { conflicts: TicketConflict[]; externalChanged: boolean; localChanged: boolean } {
  const conflicts: TicketConflict[] = [];
  const statusLocalChanged = input.local.status !== input.lastSynced.status;
  const statusExternalChanged = input.external.status !== input.lastSynced.status;
  if (statusLocalChanged && statusExternalChanged && input.local.status !== input.external.status) {
    conflicts.push({ field: "status", localValue: input.local.status, externalValue: input.external.status });
  }
  const localAssignee = input.local.assigneeReference ?? null;
  const externalAssignee = input.external.assigneeReference ?? null;
  const syncedAssignee = input.lastSynced.assigneeReference ?? null;
  const assigneeLocalChanged = localAssignee !== syncedAssignee;
  const assigneeExternalChanged = externalAssignee !== syncedAssignee;
  if (assigneeLocalChanged && assigneeExternalChanged && localAssignee !== externalAssignee) {
    conflicts.push({ field: "assignee", localValue: localAssignee, externalValue: externalAssignee });
  }
  return {
    conflicts,
    externalChanged: statusExternalChanged || assigneeExternalChanged,
    localChanged: statusLocalChanged || assigneeLocalChanged,
  };
}
