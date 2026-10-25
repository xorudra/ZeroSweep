import { scrubSecretPatterns } from "../integrations/sanitize";

/**
 * External ticket payload construction (Prompt 31 §43–§45). The payload
 * is built from SAFE fields only — title, severity, priority, affected
 * asset, CVE/CWE, a plain-language risk explanation, the safe
 * remediation summary and the due date — and then runs through secret
 * scrubbing as a second line of defence. Restricted evidence
 * (credentials, tokens, request/response bodies) is never an input
 * (§44), so it can never reach an external tracker (§147).
 */
export interface TicketFindingView {
  id: string;
  title: string;
  severity: string;
  priority?: string | null;
  host?: string | null;
  endpoint?: string | null;
  cve?: string | null;
  cwe?: string | null;
  riskExplanation?: string | null;
  remediationSummary?: string | null;
}

export interface TicketPayload {
  title: string;
  body: string;
  severity: string;
  priority: string | null;
  dueAt: string | null;
  labels: string[];
  dsrcloneRef: string;
  redactions: string[];
}

export function buildTicketPayload(input: {
  finding: TicketFindingView;
  caseId: string;
  dueAt?: Date | null;
}): TicketPayload {
  const { finding } = input;
  const asset = finding.host ?? finding.endpoint ?? "asset reference withheld";
  const lines = [
    `Severity: ${finding.severity}${finding.priority ? ` · Priority: ${finding.priority}` : ""}`,
    `Affected asset: ${asset}`,
    finding.cve ? `CVE: ${finding.cve}` : null,
    finding.cwe ? `CWE: ${finding.cwe}` : null,
    finding.riskExplanation ? `Risk: ${finding.riskExplanation}` : null,
    finding.remediationSummary ? `Safe remediation summary: ${finding.remediationSummary}` : null,
    input.dueAt ? `Remediation due: ${input.dueAt.toISOString()}` : null,
    `ZeroSweep remediation case: ${input.caseId}`,
    "Note: closing this ticket does not close the vulnerability in ZeroSweep — the fix is verified independently.",
  ].filter((l): l is string => l !== null);
  const rawTitle = `[${finding.severity}] ${finding.title}`;
  const title = scrubSecretPatterns(rawTitle);
  const body = scrubSecretPatterns(lines.join("\n"));
  return {
    title: title.text,
    body: body.text,
    severity: finding.severity,
    priority: finding.priority ?? null,
    dueAt: input.dueAt ? input.dueAt.toISOString() : null,
    labels: ["dsrclone", "security-remediation", ...(finding.cve ? ["kev-watch"] : [])],
    dsrcloneRef: input.caseId,
    redactions: [...title.redactions, ...body.redactions],
  };
}

/** Stable work-item idempotency key (§46): one key per case+provider,
 *  so a retried create returns the existing work item. */
export function workItemIdempotencyKey(caseId: string, provider: string): string {
  return `remediation:${caseId}:${provider.toLowerCase()}`;
}

/** Ticket staleness (§39): a synced ticket untouched beyond the window
 *  is STALE — surfaced, never silently trusted. */
export function isWorkItemStale(input: { status: string; lastSyncedAt: Date | null; createdAt: Date }, now: Date, staleAfterMs = 7 * 24 * 3600 * 1000): boolean {
  if (input.status !== "CREATED" && input.status !== "SYNCED") return false;
  const anchor = input.lastSyncedAt ?? input.createdAt;
  return now.getTime() - anchor.getTime() > staleAfterMs;
}
