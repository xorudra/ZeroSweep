/**
 * Live event stream contract (Prompt 4 §40–§41, §44, §55).
 * Events are DURABLE first: the API persists every lifecycle event to the
 * ScanEvent table (the source of truth / timeline), and SSE is only the
 * presentation transport on top of that record. Payloads never carry secrets,
 * credentials or raw tool output.
 */

export const SCAN_EVENT_TYPES = [
  "scan.created", "scan.queued", "scan.started", "scan.progress",
  "scan.paused", "scan.resumed",
  "stage.ready", "stage.started", "stage.progress", "stage.completed", "stage.failed", "stage.skipped",
  "tool.queued", "tool.started", "tool.completed", "tool.failed",
  "finding.created", "asset.discovered", "asset.out_of_scope", "endpoint.discovered",
  "scan.completed", "scan.failed", "scan.cancelled",
  "policy.denied", "scope.violation",
] as const;
export type ScanEventType = (typeof SCAN_EVENT_TYPES)[number];

export interface ScanEventRecord {
  id?: string;
  scanId: string;
  workspaceId: string;
  type: ScanEventType;
  /** Safe, non-sensitive metadata only — ids, statuses, counts. */
  payload: Record<string, string | number | boolean | null>;
  createdAt: string;
}

export function makeEvent(
  scanId: string,
  workspaceId: string,
  type: ScanEventType,
  payload: ScanEventRecord["payload"] = {},
  at: Date = new Date(),
): ScanEventRecord {
  return { scanId, workspaceId, type, payload, createdAt: at.toISOString() };
}
