import { sha256Hex } from "../identity/crypto";

/**
 * Canonical analytics event (Prompt 27 §4–§13).
 *
 * The lake is APPEND-ONLY: events are never rewritten when current
 * state changes (§7); corrections arrive as new events. eventId is
 * the stable idempotency key (§9). Tenant context is validated before
 * landing (§12) and attributes are size-bounded summaries/references
 * only (§13) — raw artifacts stay in object storage, secrets never
 * enter an event (§111).
 */

export const ANALYTICS_SCHEMA_VERSION = "1.0";
export const MAX_EVENT_BYTES = 16_384; // §13 bounded event size
export const MAX_ATTRIBUTES_BYTES = 8_192;

export const ANALYTICS_EVENT_TYPES = [
  "ASSET_DISCOVERED", "ASSET_CHANGED", "ASSET_REMOVED", "ASSET_EXPOSURE_CHANGED",
  "FINDING_CREATED", "FINDING_UPDATED", "FINDING_VERIFIED", "FINDING_RESOLVED",
  "FINDING_REOPENED", "FINDING_REGRESSED",
  "SCAN_STARTED", "SCAN_COMPLETED", "SCAN_FAILED",
  "RISK_CHANGED", "TECHNOLOGY_DETECTED", "SERVICE_EXPOSED",
  "KEV_DETECTED", "EPSS_CHANGED", "SECRET_DETECTED",
  "SOURCE_SECURITY_CHANGED", "PIPELINE_GATE_FAILED",
  "CONTROL_FAILED", "CONTROL_RECOVERED", "COMPLIANCE_DRIFT",
  "AUTH_SECURITY_EVENT", "REMEDIATION_TICKET_CHANGED",
] as const;
export type AnalyticsEventType = (typeof ANALYTICS_EVENT_TYPES)[number];

export const ANALYTICS_CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;
export type AnalyticsClassification = (typeof ANALYTICS_CLASSIFICATIONS)[number];

export function analyticsClassificationRank(c: string): number {
  const i = (ANALYTICS_CLASSIFICATIONS as readonly string[]).indexOf(c);
  return i < 0 ? 1 : i; // unknown → INTERNAL rank (never silently PUBLIC)
}

export interface AnalyticsEventInput {
  eventId: string;
  organizationId: string;
  workspaceId: string;
  eventType: string;
  eventTime: string; // ISO-8601
  sourceType: string;
  sourceId?: string | null;
  resourceType: string;
  resourceId: string;
  assetId?: string | null;
  findingId?: string | null;
  scanId?: string | null;
  severity?: string | null;
  priority?: string | null;
  riskScore?: number | null;
  classification?: string;
  schemaVersion?: string;
  attributes?: Record<string, unknown>;
}

const SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);
const FUTURE_SKEW_MS = 5 * 60_000; // producer clocks may drift slightly; beyond that the event is invalid

/**
 * §12 validation. Returns a list of stable error codes (empty = valid).
 * Every rejection lands in the dead-letter with these codes (§11).
 */
export function validateAnalyticsEvent(input: AnalyticsEventInput, now = new Date()): string[] {
  const errors: string[] = [];
  if (!input || typeof input !== "object") return ["EVENT_NOT_OBJECT"];
  if (!input.eventId || typeof input.eventId !== "string") errors.push("EVENT_ID_MISSING");
  if (!input.organizationId) errors.push("ORGANIZATION_MISSING");
  if (!input.workspaceId) errors.push("WORKSPACE_MISSING");
  if (!(ANALYTICS_EVENT_TYPES as readonly string[]).includes(input.eventType)) errors.push("EVENT_TYPE_UNKNOWN");
  if (!input.resourceType || !input.resourceId) errors.push("RESOURCE_REFERENCE_MISSING");
  const t = new Date(input.eventTime);
  if (Number.isNaN(t.getTime())) errors.push("EVENT_TIME_INVALID");
  else if (t.getTime() > now.getTime() + FUTURE_SKEW_MS) errors.push("EVENT_TIME_IN_FUTURE");
  if (input.severity != null && !SEVERITIES.has(input.severity)) errors.push("SEVERITY_UNKNOWN");
  if (input.riskScore != null && (typeof input.riskScore !== "number" || input.riskScore < 0 || input.riskScore > 100)) errors.push("RISK_SCORE_OUT_OF_RANGE");
  const classification = input.classification ?? "INTERNAL";
  if (!(ANALYTICS_CLASSIFICATIONS as readonly string[]).includes(classification)) errors.push("CLASSIFICATION_UNKNOWN");
  const version = input.schemaVersion ?? ANALYTICS_SCHEMA_VERSION;
  if (!/^\d+\.\d+$/.test(version)) errors.push("SCHEMA_VERSION_INVALID");
  try {
    const bytes = Buffer.byteLength(JSON.stringify(input.attributes ?? {}), "utf8");
    if (bytes > MAX_ATTRIBUTES_BYTES) errors.push("ATTRIBUTES_TOO_LARGE");
  } catch { errors.push("ATTRIBUTES_NOT_SERIALIZABLE"); }
  try {
    if (Buffer.byteLength(JSON.stringify(input), "utf8") > MAX_EVENT_BYTES) errors.push("EVENT_TOO_LARGE");
  } catch { errors.push("EVENT_NOT_SERIALIZABLE"); }
  return errors;
}

/** Canonical (key-sorted) JSON — the checksum basis for lineage (§8). */
export function canonicalEventJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalEventJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : 1));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalEventJson(v)}`).join(",")}}`;
}

export function analyticsEventChecksum(input: AnalyticsEventInput): string {
  const { eventId, organizationId, workspaceId, eventType, eventTime, sourceType, sourceId, resourceType, resourceId, assetId, findingId, scanId, severity, priority, riskScore, classification, schemaVersion, attributes } = input;
  return sha256Hex(canonicalEventJson({
    eventId, organizationId, workspaceId, eventType, eventTime, sourceType, sourceId: sourceId ?? null,
    resourceType, resourceId, assetId: assetId ?? null, findingId: findingId ?? null, scanId: scanId ?? null,
    severity: severity ?? null, priority: priority ?? null, riskScore: riskScore ?? null,
    classification: classification ?? "INTERNAL", schemaVersion: schemaVersion ?? ANALYTICS_SCHEMA_VERSION,
    attributes: attributes ?? {},
  }));
}
