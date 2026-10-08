import { createHash } from "node:crypto";

/**
 * Prompt 37 §49–§59: vulnerability-platform sync semantics for
 * DefectDojo, Faraday, Dradis and PlexTrac.
 *
 * DSRclone is canonical for its own finding IDs and lifecycle (§51);
 * external systems are integrations. This module is the pure decision
 * layer the API sync service executes:
 *  - status/severity mapping in both directions (§49/§52–§54);
 *  - conflict detection — a conflict exists when BOTH sides changed
 *    the same field since the last sync (§57). Conflicts are data,
 *    returned for surfacing; nothing here overwrites anything (§58);
 *  - loop prevention — every record that crosses the boundary carries
 *    a content hash; an inbound record whose hash equals the last
 *    hash we sent/received for that external id is our own echo and
 *    is skipped (§59).
 */
export const VULN_SYNC_PROVIDERS = ["DEFECTDOJO", "FARADAY", "DRADIS", "PLEXTRAC"] as const;
export type VulnSyncProvider = (typeof VULN_SYNC_PROVIDERS)[number];

export const SYNC_MODES = ["PUSH", "PULL", "BIDIRECTIONAL_METADATA"] as const;
export type SyncMode = (typeof SYNC_MODES)[number];
export const CONFLICT_POLICIES = ["MANUAL", "KEEP_LOCAL", "TAKE_EXTERNAL_METADATA"] as const;
export type ConflictPolicy = (typeof CONFLICT_POLICIES)[number];

/** Canonical (DSRclone) lifecycle → external status vocabulary (§49). */
const STATUS_TO_EXTERNAL: Record<string, string> = {
  NEW: "Active", TRIAGED: "Active", CONFIRMED: "Active", IN_PROGRESS: "Active",
  REMEDIATED: "Mitigated", RETEST_PENDING: "Mitigated", RESOLVED: "Closed",
  FALSE_POSITIVE: "False Positive", ACCEPTED_RISK: "Risk Accepted",
  REOPENED: "Active", DUPLICATE: "Duplicate", MITIGATED: "Mitigated",
};
const EXTERNAL_TO_STATUS: Record<string, string> = {
  "active": "CONFIRMED", "verified": "CONFIRMED", "mitigated": "REMEDIATED",
  "closed": "RESOLVED", "false positive": "FALSE_POSITIVE", "false_positive": "FALSE_POSITIVE",
  "risk accepted": "ACCEPTED_RISK", "risk_accepted": "ACCEPTED_RISK",
  "duplicate": "DUPLICATE", "out of scope": "DUPLICATE", "under review": "TRIAGED",
};

export function externalStatusFor(canonicalLifecycle: string): string {
  return STATUS_TO_EXTERNAL[canonicalLifecycle] ?? "Active";
}
export function canonicalStatusFor(externalStatus: string): string | null {
  return EXTERNAL_TO_STATUS[externalStatus.trim().toLowerCase()] ?? null;
}

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"] as const;
export function normalizeSyncSeverity(raw: string): string {
  const v = raw.trim().toUpperCase();
  if ((SEVERITIES as readonly string[]).includes(v)) return v;
  if (v === "INFO" || v === "NONE") return "INFORMATIONAL";
  if (v === "MODERATE") return "MEDIUM";
  return "INFORMATIONAL"; // unknown severities are never inflated
}

/** Stable content fingerprint for loop prevention + change detection. */
export function syncContentHash(input: { title: string; severity: string; status: string; cve?: string | null }): string {
  return createHash("sha256")
    .update([input.title, input.severity.toUpperCase(), input.status.toUpperCase(), input.cve ?? ""].join("|"))
    .digest("hex");
}

/**
 * The echo hash of a LOCAL finding, derived exactly the way
 * decideSyncRecord derives an inbound record's hash: through the
 * external vocabulary and back. The status map is many-to-one
 * (NEW/TRIAGED/CONFIRMED all read "Active" externally), so hashing the
 * raw lifecycle would never match the returning echo (§59).
 */
export function syncEchoHashForLocal(input: { title: string; severity: string; lifecycleStatus: string; cve?: string | null }): string {
  const external = externalStatusFor(input.lifecycleStatus);
  return syncContentHash({
    title: input.title, severity: input.severity,
    status: canonicalStatusFor(external) ?? external, cve: input.cve,
  });
}

export interface SyncRecordView {
  externalId: string;
  title: string;
  severity: string;
  status: string; // external vocabulary
  cve?: string | null;
}
export interface LocalRefView {
  externalId: string;
  findingId: string | null;
  /** Local values as of the last completed sync. */
  lastSyncedSeverity: string | null;
  lastSyncedStatus: string | null; // canonical lifecycle
  contentHash: string | null;
  /** Current local values. */
  localSeverity: string | null;
  localStatus: string | null;
}

export type SyncDecision =
  | { kind: "SKIP_ECHO"; externalId: string }
  | { kind: "IMPORT_NEW"; externalId: string }
  | { kind: "UPDATE_LOCAL"; externalId: string; fields: string[] }
  | { kind: "CONFLICT"; externalId: string; fields: string[] }
  | { kind: "UNCHANGED"; externalId: string };

/**
 * Decide what one inbound record means (§57/§59). A field conflicts
 * only when BOTH sides moved away from the last-synced value; a
 * one-sided move is an update. External lifecycle truth never beats
 * local analyst decisions for closure states — a remote "Closed" for
 * a finding that was never verified locally is surfaced as an update
 * candidate for status only when the local side is unchanged, and the
 * API layer still routes it through the governed lifecycle (§51/§153).
 */
export function decideSyncRecord(inbound: SyncRecordView, ref: LocalRefView | undefined): SyncDecision {
  if (!ref || !ref.findingId) return { kind: "IMPORT_NEW", externalId: inbound.externalId };
  const inboundHash = syncContentHash({
    title: inbound.title,
    severity: normalizeSyncSeverity(inbound.severity),
    status: canonicalStatusFor(inbound.status) ?? inbound.status,
    cve: inbound.cve,
  });
  if (ref.contentHash && inboundHash === ref.contentHash) return { kind: "SKIP_ECHO", externalId: inbound.externalId };

  const extSeverity = normalizeSyncSeverity(inbound.severity);
  const extStatus = canonicalStatusFor(inbound.status);
  const fields: string[] = [];
  const conflicts: string[] = [];
  const check = (field: string, last: string | null, local: string | null, ext: string | null) => {
    if (ext === null || last === null) return;
    if (ext === local) return;
    const localChanged = local !== last;
    const extChanged = ext !== last;
    if (localChanged && extChanged) conflicts.push(field);
    else if (extChanged) fields.push(field);
  };
  check("severity", ref.lastSyncedSeverity, ref.localSeverity, extSeverity);
  check("status", ref.lastSyncedStatus, ref.localStatus, extStatus);
  if (conflicts.length) return { kind: "CONFLICT", externalId: inbound.externalId, fields: conflicts };
  if (fields.length) return { kind: "UPDATE_LOCAL", externalId: inbound.externalId, fields };
  return { kind: "UNCHANGED", externalId: inbound.externalId };
}
