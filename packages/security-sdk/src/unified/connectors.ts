import { normalizeSeverity } from "./types";
import { fingerprintV2 } from "./fingerprint-v2";
import { sanitizeImportedText, sanitizeImportedUrl, sanitizeImportedEvidence, IMPORT_LIMITS } from "./sanitize";

/**
 * VulnerabilityPlatformConnector framework (Prompt 20 §49/§50/§52–§54).
 *
 * One interface for every external vulnerability platform. The
 * invariants that hold for ALL connectors:
 *  - credentials are secret REFERENCES only — a connector never sees
 *    or stores a secret value (§50);
 *  - endpoints must be on the administrator allowlist and TLS-checked
 *    before any request leaves (§50);
 *  - the external platform is NEVER authoritative over local analyst
 *    decisions: disagreements become IntegrationConflicts (§43);
 *  - imports are previewed, bounded and idempotent (§52/§53/§97);
 *  - exports obey the administrator ExportPolicy (§54) — defaults deny
 *    raw evidence, PII, internal hostnames, snippets, secret
 *    fingerprints and screenshots.
 * A connector with no configured instance reports NOT_CONFIGURED —
 * health is never fabricated.
 */

export type ExternalSystem = "DEFECTDOJO" | "FARADAY" | "DRADIS" | "PLEXTRAC" | "SERPICO";
export type ConnectorCapability = "IMPORT" | "EXPORT" | "SYNC_FINDINGS";

export interface ConnectorInstanceConfig {
  /** Opaque endpoint NAME resolved server-side (never a user URL). */
  endpointReference: string;
  /** Name of the secret in the secret store — never the value. */
  credentialReference?: string;
  /** Administrator allowlist of endpoint references this connector may use. */
  endpointAllowlist: string[];
  /** PlexTrac (§47): commercial — capabilities unlock only when the
   *  admin confirms a licensed, configured installation exists. */
  licenseConfirmed?: boolean;
  timeoutMs?: number;
  maxRequestsPerMinute?: number;
}

export interface ConnectorPolicy {
  timeoutMs: number;
  maxRequestsPerMinute: number;
  requireTls: boolean;
}

export const DEFAULT_CONNECTOR_POLICY: ConnectorPolicy = { timeoutMs: 15_000, maxRequestsPerMinute: 60, requireTls: true };

/** §50: an endpoint reference is usable only when allowlisted. */
export function validateConnectorEndpoint(config: ConnectorInstanceConfig): { ok: boolean; error?: string } {
  if (!config.endpointReference) return { ok: false, error: "no endpoint reference configured (§50)" };
  if (!config.endpointAllowlist.includes(config.endpointReference)) {
    return { ok: false, error: `endpoint reference ${config.endpointReference} is not on the administrator allowlist (§50)` };
  }
  return { ok: true };
}

export class ConnectorNotConfiguredError extends Error {
  constructor(system: ExternalSystem) {
    super(`${system} connector is NOT_CONFIGURED — no instance/transport is provisioned`);
    this.name = "ConnectorNotConfiguredError";
  }
}

/** Transport abstraction: the API/worker wires real HTTP in production;
 *  connectors themselves never perform I/O directly. */
export interface ConnectorTransport {
  request(input: { method: "GET" | "POST" | "PUT"; path: string; body?: unknown }): Promise<unknown>;
}

export class UnconfiguredConnectorTransport implements ConnectorTransport {
  constructor(private readonly system: ExternalSystem) {}
  async request(): Promise<unknown> {
    throw new ConnectorNotConfiguredError(this.system);
  }
}

/** Deterministic fixture transport: canned responses keyed by "METHOD path". */
export class FixtureConnectorTransport implements ConnectorTransport {
  readonly calls: { method: string; path: string; body?: unknown }[] = [];
  constructor(private readonly responses: Record<string, unknown>) {}
  async request(input: { method: string; path: string; body?: unknown }): Promise<unknown> {
    this.calls.push(input);
    const key = `${input.method} ${input.path}`;
    if (!(key in this.responses)) throw new Error(`fixture transport has no response for ${key}`);
    return this.responses[key];
  }
}

export interface NormalizedExternalFinding {
  externalId: string;
  externalUrl?: string;
  title: string;
  description: string;
  severity: string; // normalized Severity
  rawSeverity?: string;
  status: string; // unified lifecycle vocabulary
  cve?: string;
  cwe?: string;
  host?: string;
  endpoint?: string;
  evidence?: string; // sanitized + redacted (§51/§63)
  fingerprint: string;
}

export interface ConnectorHealth {
  status: "NOT_CONFIGURED" | "HEALTHY" | "DEGRADED" | "UNAVAILABLE" | "LICENSE_UNAVAILABLE";
  detail: string;
}

export interface ExportPolicy {
  includeRawEvidence: boolean;
  includePii: boolean;
  includeInternalHostnames: boolean;
  includeSourceSnippets: boolean;
  includeSecretFingerprints: boolean;
  includeScreenshots: boolean;
}

export const DEFAULT_EXPORT_POLICY: ExportPolicy = {
  includeRawEvidence: false,
  includePii: false,
  includeInternalHostnames: false,
  includeSourceSnippets: false,
  includeSecretFingerprints: false,
  includeScreenshots: false,
};

/** §54: shape a local finding for export under the policy. */
export function applyExportPolicy(
  finding: { title: string; description: string; severity: string; status: string; cve?: string | null; cwe?: string | null; host?: string | null; evidenceSummary?: string | null; secretFingerprint?: string | null },
  policy: ExportPolicy,
): Record<string, unknown> {
  const out: Record<string, unknown> = {
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    status: finding.status,
    ...(finding.cve ? { cve: finding.cve } : {}),
    ...(finding.cwe ? { cwe: finding.cwe } : {}),
  };
  if (policy.includeInternalHostnames && finding.host) out.host = finding.host;
  if (policy.includeRawEvidence && finding.evidenceSummary) out.evidence = finding.evidenceSummary;
  if (policy.includeSecretFingerprints && finding.secretFingerprint) out.secretFingerprint = finding.secretFingerprint;
  return out;
}

export interface VulnerabilityPlatformConnector {
  readonly system: ExternalSystem;
  capabilities(config: ConnectorInstanceConfig): ConnectorCapability[];
  healthCheck(config: ConnectorInstanceConfig, transport: ConnectorTransport): Promise<ConnectorHealth>;
  importFindings(config: ConnectorInstanceConfig, transport: ConnectorTransport, workspaceId: string): Promise<NormalizedExternalFinding[]>;
  exportFindings(config: ConnectorInstanceConfig, transport: ConnectorTransport, findings: Record<string, unknown>[]): Promise<{ exported: number; externalIds: string[] }>;
  mapStatus(externalStatus: string): string;
  mapSeverity(externalSeverity: string): string;
  toExternalStatus(unifiedStatus: string): string;
}

/** Shared normalization for one external record (§51 sanitization funnel). */
export function normalizeExternalRecord(
  workspaceId: string,
  rec: {
    externalId: string;
    externalUrl?: unknown;
    title: unknown;
    description?: unknown;
    severity: string;
    rawSeverity?: string;
    status: string;
    cve?: string;
    cwe?: string;
    host?: string;
    endpoint?: string;
    evidence?: unknown;
    sourceDomain?: string;
  },
): NormalizedExternalFinding {
  const title = sanitizeImportedText(rec.title, IMPORT_LIMITS.maxTitleLength) || "(untitled imported finding)";
  return {
    externalId: String(rec.externalId),
    ...(sanitizeImportedUrl(rec.externalUrl) ? { externalUrl: sanitizeImportedUrl(rec.externalUrl) } : {}),
    title,
    description: sanitizeImportedText(rec.description, IMPORT_LIMITS.maxDescriptionLength),
    severity: normalizeSeverity(rec.severity),
    rawSeverity: rec.rawSeverity ?? rec.severity,
    status: rec.status,
    ...(rec.cve ? { cve: rec.cve.toUpperCase() } : {}),
    ...(rec.cwe ? { cwe: rec.cwe.toUpperCase() } : {}),
    ...(rec.host ? { host: rec.host } : {}),
    ...(rec.endpoint ? { endpoint: rec.endpoint } : {}),
    ...(rec.evidence !== undefined ? { evidence: sanitizeImportedEvidence(rec.evidence) } : {}),
    fingerprint: fingerprintV2({
      workspaceId,
      sourceDomain: rec.sourceDomain ?? "EXTERNAL_IMPORT",
      host: rec.host,
      endpoint: rec.endpoint,
      cve: rec.cve,
      cwe: rec.cwe,
      ruleId: title.toLowerCase(),
    }),
  };
}

// ---------------- Import preview, idempotency, conflicts (§43/§52/§53) ----------------

export interface ImportPreview {
  newFindings: NormalizedExternalFinding[];
  potentialDuplicates: { incoming: NormalizedExternalFinding; existingFindingId: string }[];
  updates: { incoming: NormalizedExternalFinding; existingFindingId: string }[];
  conflicts: SyncConflictDraft[];
  invalid: { externalId: string; reason: string }[];
}

export interface SyncConflictDraft {
  findingId?: string;
  externalId: string;
  field: "status" | "severity" | "ownership" | "external_closed";
  localValue?: string;
  externalValue?: string;
}

export interface ExistingExternalState {
  /** externalId → local finding id + last-synced status/severity. */
  byExternalId: Map<string, { findingId: string; status: string; severity: string; ownerRef?: string }>;
  /** canonical fingerprint → local finding id. */
  byFingerprint: Map<string, string>;
}

/**
 * §52/§53: preview an import against existing state. Idempotency key =
 * (integration, externalId); a repeat import of the same record is an
 * UPDATE candidate, never a new finding. A fingerprint match with a
 * different external record is a POTENTIAL DUPLICATE for an analyst —
 * imports never merge silently either.
 */
export function computeImportPreview(incoming: NormalizedExternalFinding[], existing: ExistingExternalState): ImportPreview {
  const preview: ImportPreview = { newFindings: [], potentialDuplicates: [], updates: [], conflicts: [], invalid: [] };
  for (const rec of incoming) {
    if (!rec.externalId) { preview.invalid.push({ externalId: "", reason: "record has no external id — cannot be idempotently imported (§53)" }); continue; }
    const known = existing.byExternalId.get(rec.externalId);
    if (known) {
      preview.updates.push({ incoming: rec, existingFindingId: known.findingId });
      preview.conflicts.push(...detectSyncConflicts({ findingId: known.findingId, externalId: rec.externalId, localStatus: known.status, localSeverity: known.severity, localOwnerRef: known.ownerRef }, rec));
      continue;
    }
    const fpMatch = existing.byFingerprint.get(rec.fingerprint);
    if (fpMatch) { preview.potentialDuplicates.push({ incoming: rec, existingFindingId: fpMatch }); continue; }
    preview.newFindings.push(rec);
  }
  return preview;
}

/** §43/§107: disagreements are conflicts, never silent overwrites.
 *  The sharpest case: local IN_PROGRESS vs external CLOSED. */
export function detectSyncConflicts(
  local: { findingId: string; externalId: string; localStatus: string; localSeverity: string; localOwnerRef?: string },
  external: NormalizedExternalFinding & { ownerRef?: string },
): SyncConflictDraft[] {
  const conflicts: SyncConflictDraft[] = [];
  const externalClosed = external.status === "RESOLVED";
  const localClosed = local.localStatus === "RESOLVED" || local.localStatus === "FALSE_POSITIVE";
  if (externalClosed && !localClosed) {
    conflicts.push({ findingId: local.findingId, externalId: local.externalId, field: "external_closed", localValue: local.localStatus, externalValue: external.status });
  } else if (external.status !== local.localStatus && !(external.status === "CONFIRMED" && local.localStatus === "IN_PROGRESS")) {
    conflicts.push({ findingId: local.findingId, externalId: local.externalId, field: "status", localValue: local.localStatus, externalValue: external.status });
  }
  if (external.severity !== local.localSeverity) {
    conflicts.push({ findingId: local.findingId, externalId: local.externalId, field: "severity", localValue: local.localSeverity, externalValue: external.severity });
  }
  if (external.ownerRef && local.localOwnerRef && external.ownerRef !== local.localOwnerRef) {
    conflicts.push({ findingId: local.findingId, externalId: local.externalId, field: "ownership", localValue: local.localOwnerRef, externalValue: external.ownerRef });
  }
  return conflicts;
}
