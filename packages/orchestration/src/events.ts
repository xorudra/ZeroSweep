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
  "finding.created", "finding.correlated", "finding.normalized", "risk.calculated",
  "asset.discovered", "asset.out_of_scope", "endpoint.discovered",
  "scan.completed", "scan.failed", "scan.cancelled",
  "policy.denied", "scope.violation",
  // Prompt 8 — proxy scanner connector lifecycle + passive analysis.
  // Payloads carry ids/counts/statuses only: never secrets, never traffic.
  "scanner.context_created", "scanner.context_destroyed",
  "passive_analysis.started", "passive_analysis.completed", "passive_analysis.skipped",
  "auth_session.expired", "active_scan.denied",
  // Prompt 9 — API security engine events (§78). Counts/ids/verdicts only.
  "api.service_discovered", "api.spec_imported", "api.operation_blocked",
  "jwt.analyzed", "graphql.schema_imported", "api.test_completed",
  "api.auth_mapped", "websocket.inventoried",
  // Prompt 10 — network VAPT engine events (§84). Counts/ids/verdicts
  // only; never per-packet data, never raw tool output.
  "network.targets_expanded", "network.host_discovered", "network.port_discovered",
  "network.service_identified", "network.protected_target_blocked",
  "network.internal_scan_approved", "network.masscan_denied",
  "network.local_discovery_unavailable", "network.scan_completed",
  // Prompt 12 — source code security events (§96). Counts/ids/verdicts
  // only; a secret event NEVER carries the secret value (§110).
  "source.snapshot_created", "source.languages_detected",
  "source.secret_detected", "source.dependency_vulnerability_detected",
  "source.dependencies_inventoried", "source.sbom_generated",
  "source.quality_gate_evaluated", "source.scan_completed",
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
