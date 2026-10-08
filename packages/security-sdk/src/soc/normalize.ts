import { createHash } from "node:crypto";
import { scrubSecretPatterns } from "../integrations/sanitize";
import {
  SOC_CLASSIFICATIONS, SOC_SEVERITIES, TELEMETRY_SOURCE_CATEGORIES,
  type CanonicalTelemetryEvent, type SocClassification, type SocSeverity,
} from "./types";

/**
 * Telemetry normalization + ingestion hygiene (Prompt 28 §5–§13).
 *
 * Provider-specific events are normalized into canonical fields; the
 * original event is preserved BY REFERENCE only (§5/§6). Attributes
 * are secret-scrubbed before storage (§157): a fake token planted in
 * telemetry must never reach the canonical store, search, alerts or
 * AI context. Ingestion is idempotent (§11): the fingerprint is the
 * provider event ID when present, otherwise a stable hash of the
 * canonical identity fields.
 */

export const TELEMETRY_SCHEMA_VERSION = "1.0";
export const MAX_TELEMETRY_ATTRIBUTES = 40;
export const MAX_TELEMETRY_PAYLOAD_BYTES = 64 * 1024;
export const MAX_ATTRIBUTE_VALUE_CHARS = 512;

const SEVERITY_SET = new Set<string>(SOC_SEVERITIES);
const CLASSIFICATION_SET = new Set<string>(SOC_CLASSIFICATIONS);
const CATEGORY_SET = new Set<string>(TELEMETRY_SOURCE_CATEGORIES);

export interface NormalizationResult {
  ok: boolean;
  event?: CanonicalTelemetryEvent;
  fingerprint?: string;
  contentHash?: string;
  redactions: string[];
  errors: string[];
}

function asString(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

function pick(obj: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) { const v = asString(obj[k]); if (v) return v; }
  return undefined;
}

/** Scrub + bound an attributes bag. Keys sorted for a stable hash. */
export function sanitizeTelemetryAttributes(input: unknown): { attributes: Record<string, unknown>; redactions: string[] } {
  const redactions: string[] = [];
  if (!input || typeof input !== "object" || Array.isArray(input)) return { attributes: {}, redactions };
  const out: Record<string, unknown> = {};
  const entries = Object.entries(input as Record<string, unknown>)
    .filter(([k]) => /^[a-zA-Z0-9_.-]{1,64}$/.test(k))
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .slice(0, MAX_TELEMETRY_ATTRIBUTES);
  for (const [key, value] of entries) {
    // §157: secret-bearing attribute KEYS are redacted wholesale —
    // telemetry never stores credential material, whatever its shape.
    if (/(token|password|passwd|pwd|secret|api[_-]?key|credential|authorization|cookie)/i.test(key)) {
      redactions.push(`secret attribute:${key}`);
      out[key] = "[REDACTED]";
      continue;
    }
    if (typeof value === "string") {
      const scrubbed = scrubSecretPatterns(value.slice(0, MAX_ATTRIBUTE_VALUE_CHARS));
      redactions.push(...scrubbed.redactions);
      out[key] = scrubbed.text;
    } else if (typeof value === "number" || typeof value === "boolean") {
      out[key] = value;
    } else if (Array.isArray(value)) {
      out[key] = value.slice(0, 16).map((v) => (typeof v === "string" ? scrubSecretPatterns(v.slice(0, 128)).text : v)).filter((v) => ["string", "number", "boolean"].includes(typeof v));
    }
    // nested objects are dropped: canonical attributes are flat (§5).
  }
  return { attributes: out, redactions };
}

/**
 * Normalize a provider event. `provider` shapes are recognized by
 * sourceCategory; unknown shapes fall back to the canonical field
 * names. This is a *mapping*, never an execution: nothing in the
 * payload is evaluated (§18).
 */
export function normalizeTelemetryEvent(raw: unknown): NormalizationResult {
  const errors: string[] = [];
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, errors: ["EVENT_NOT_OBJECT"], redactions: [] };
  }
  const r = raw as Record<string, unknown>;
  if (JSON.stringify(r).length > MAX_TELEMETRY_PAYLOAD_BYTES) {
    return { ok: false, errors: ["EVENT_TOO_LARGE"], redactions: [] };
  }
  const sourceCategory = pick(r, ["sourceCategory", "category", "source_category"]) ?? "DSRCLONE_INTERNAL";
  if (!CATEGORY_SET.has(sourceCategory)) errors.push("SOURCE_CATEGORY_UNKNOWN");
  const source = pick(r, ["source", "provider", "sourceName"]) ?? sourceCategory.toLowerCase();
  const eventTimeRaw = pick(r, ["eventTime", "timestamp", "time", "@timestamp", "event_time"]);
  const eventTime = eventTimeRaw ? new Date(eventTimeRaw) : new Date(NaN);
  if (Number.isNaN(eventTime.getTime())) errors.push("EVENT_TIME_INVALID");
  const severityRaw = (pick(r, ["severity", "level"]) ?? "INFO").toUpperCase();
  const severity = (SEVERITY_SET.has(severityRaw) ? severityRaw : "INFO") as SocSeverity;
  const classificationRaw = (pick(r, ["classification"]) ?? "INTERNAL").toUpperCase();
  const classification = (CLASSIFICATION_SET.has(classificationRaw) ? classificationRaw : "INTERNAL") as SocClassification;

  // Provider-shaped field extraction (authentication + generic).
  const attrsIn: Record<string, unknown> = {
    ...((r.attributes as Record<string, unknown> | undefined) ?? {}),
  };
  const flattened: Array<[string, unknown]> = [
    ["user", pick(r, ["user", "username", "actor", "userPrincipalName"])],
    ["sourceIp", pick(r, ["sourceIp", "srcIp", "clientIp", "ip", "remoteAddress"])],
    ["outcome", pick(r, ["outcome", "result", "status"])],
    ["actionDetail", pick(r, ["actionDetail", "operation", "eventName", "event_name"])],
  ];
  for (const [k, v] of flattened) if (v !== undefined && attrsIn[k] === undefined) attrsIn[k] = v;

  const { attributes, redactions } = sanitizeTelemetryAttributes(attrsIn);
  const identityReference = pick(r, ["identityReference", "userId", "actorId", "principalId"])
    ?? asString(attributes.user);
  const event: CanonicalTelemetryEvent = {
    providerEventId: pick(r, ["providerEventId", "eventId", "event_id", "id"]),
    eventTime: eventTime.toISOString(),
    source,
    sourceCategory,
    eventCategory: pick(r, ["eventCategory", "event_category", "category"]) ?? sourceCategory,
    eventAction: pick(r, ["eventAction", "action", "event_name", "eventName"]) ?? "UNKNOWN",
    assetId: pick(r, ["assetId", "asset_id", "resourceId"]),
    identityReference,
    severity,
    classification,
    attributes,
    rawReference: pick(r, ["rawReference", "raw_reference"]),
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
  };
  if (errors.length > 0) return { ok: false, errors, redactions };
  return { ok: true, event, fingerprint: telemetryFingerprint(event), contentHash: telemetryContentHash(event), redactions, errors: [] };
}

/** §11: stable logical identity of an event within a workspace. */
export function telemetryFingerprint(event: CanonicalTelemetryEvent): string {
  if (event.providerEventId) return `prov:${event.source}:${event.providerEventId}`;
  const basis = [event.source, event.eventTime, event.eventCategory, event.eventAction, event.assetId ?? "", event.identityReference ?? ""].join("|");
  return `fp:${createHash("sha256").update(basis).digest("hex").slice(0, 32)}`;
}

/** §7: integrity hash over the canonical event body. Historical
 *  evidence referenced by incidents is verified against this hash;
 *  silent mutation makes verification fail (§143). */
export function telemetryContentHash(event: CanonicalTelemetryEvent): string {
  const canonical = JSON.stringify({
    t: event.eventTime, s: event.source, sc: event.sourceCategory, ec: event.eventCategory,
    ea: event.eventAction, a: event.assetId ?? null, i: event.identityReference ?? null,
    sev: event.severity, cls: event.classification, attrs: event.attributes, v: event.schemaVersion,
  });
  return createHash("sha256").update(canonical).digest("hex");
}

export function verifyTelemetryHash(event: CanonicalTelemetryEvent, expectedHash: string): boolean {
  return telemetryContentHash(event) === expectedHash;
}
