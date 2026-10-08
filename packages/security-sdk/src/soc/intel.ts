import type { IndicatorType } from "./types";

/**
 * Threat intelligence normalization (Prompt 28 §60–§66).
 *
 * Indicators are DEFENSIVE context. Every indicator carries source
 * provenance, a deterministic confidence and a validity window; an
 * expired indicator produces no new active detections by default
 * (§66), and one low-confidence feed never classifies an event as
 * malicious on its own (§69/§140). STIX ingestion is a strict,
 * size-capped parse of indicator objects only — references are
 * validated, arbitrary STIX content is not executed or trusted (§60).
 */

export const MAX_STIX_OBJECTS = 5000;
export const MAX_STIX_BUNDLE_BYTES = 5 * 1024 * 1024;

export function normalizeIndicatorValue(type: IndicatorType, value: string): string | null {
  const v = value.trim();
  if (!v || v.length > 2048) return null;
  switch (type) {
    case "IP": {
      const parts = v.split(".");
      if (parts.length !== 4) return null;
      for (const p of parts) { const n = Number(p); if (!Number.isInteger(n) || n < 0 || n > 255 || String(n) !== p) return null; }
      return v;
    }
    case "DOMAIN":
    case "EMAIL_DOMAIN": {
      const d = v.toLowerCase().replace(/\.$/, "");
      return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/.test(d) ? d : null;
    }
    case "URL": {
      try {
        const u = new URL(v);
        if (u.protocol !== "http:" && u.protocol !== "https:") return null;
        u.hostname = u.hostname.toLowerCase();
        return u.toString();
      } catch { return null; }
    }
    case "FILE_HASH": {
      const h = v.toLowerCase();
      return /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$/.test(h) ? h : null;
    }
    case "CERTIFICATE_FINGERPRINT": {
      const h = v.replace(/[: ]/g, "").toLowerCase();
      return /^([a-f0-9]{40}|[a-f0-9]{64})$/.test(h) ? h : null;
    }
    default: return null;
  }
}

export function detectIndicatorType(value: string): IndicatorType | null {
  if (normalizeIndicatorValue("IP", value)) return "IP";
  if (normalizeIndicatorValue("FILE_HASH", value)) return "FILE_HASH";
  if (/^https?:\/\//i.test(value)) return "URL";
  if (normalizeIndicatorValue("DOMAIN", value)) return "DOMAIN";
  return null;
}

/** §63: deterministic confidence. Source trust dominates; recency
 *  decays; corroboration across independent sources adds a bounded
 *  bonus; an analyst override is taken as recorded (audited upstream). */
export function computeIndicatorConfidence(input: {
  sourceTrust: number; // 0..100, from the source record
  observedAt: Date;
  now: Date;
  independentSourceCount: number;
  analystConfidence?: number; // 0..100 when an analyst recorded one
}): number {
  if (input.analystConfidence !== undefined) {
    return Math.max(0, Math.min(100, Math.round(input.analystConfidence)));
  }
  const ageDays = Math.max(0, (input.now.getTime() - input.observedAt.getTime()) / 86400000);
  const recencyFactor = ageDays <= 7 ? 1 : ageDays <= 30 ? 0.85 : ageDays <= 90 ? 0.65 : 0.4;
  const corroboration = Math.min(15, Math.max(0, input.independentSourceCount - 1) * 5);
  return Math.max(0, Math.min(100, Math.round(input.sourceTrust * recencyFactor + corroboration)));
}

export function indicatorIsActiveForDetection(input: {
  status: string;
  validUntil?: Date | string | null;
  now: Date;
  allowHistoricalCorrelation?: boolean;
}): boolean {
  if (input.status === "REVOKED" || input.status === "FALSE_POSITIVE") return false;
  let expired = input.status === "EXPIRED";
  if (input.validUntil) {
    const until = input.validUntil instanceof Date ? input.validUntil : new Date(input.validUntil);
    if (!Number.isNaN(until.getTime()) && until.getTime() < input.now.getTime()) expired = true;
  }
  // §66: expired indicators produce no NEW active detections unless
  // policy explicitly allows historical correlation.
  if (expired) return input.allowHistoricalCorrelation === true;
  return input.status === "ACTIVE";
}

export interface ParsedStixIndicator {
  type: IndicatorType;
  valueNormalized: string;
  confidence?: number;
  labels: string[];
  validFrom?: string;
  validUntil?: string;
  externalReferences: string[];
  stixId: string;
}

const STIX_TYPE_MAP: Record<string, IndicatorType> = {
  "ipv4-addr": "IP", "ipv6-addr": "IP", "domain-name": "DOMAIN", "url": "URL",
  "file": "FILE_HASH", "email-addr": "EMAIL_DOMAIN", "x509-certificate": "CERTIFICATE_FINGERPRINT",
};

/** Extract indicator values from a STIX pattern like
 *  `[domain-name:value = 'evil.example']` — string extraction only,
 *  the pattern language is never evaluated. */
function extractPatternValue(pattern: string): { stixType: string; value: string } | null {
  const m = pattern.match(/\[\s*([a-z0-9-]+):(?:value|hashes\.'SHA-256'|hashes\.'SHA256'|hashes\.'MD5'|hashes\.'SHA-1'|serial_number)\s*=\s*'([^']+)'\s*\]/i);
  if (!m) return null;
  return { stixType: m[1].toLowerCase(), value: m[2] };
}

export function parseStixBundle(input: unknown): { indicators: ParsedStixIndicator[]; errors: string[]; skipped: number } {
  const errors: string[] = [];
  const indicators: ParsedStixIndicator[] = [];
  let skipped = 0;
  if (JSON.stringify(input ?? "").length > MAX_STIX_BUNDLE_BYTES) return { indicators, errors: ["STIX_TOO_LARGE"], skipped };
  if (!input || typeof input !== "object") return { indicators, errors: ["STIX_NOT_OBJECT"], skipped };
  const bundle = input as Record<string, unknown>;
  const objects = Array.isArray(bundle.objects) ? bundle.objects : [];
  if (objects.length > MAX_STIX_OBJECTS) return { indicators, errors: ["STIX_TOO_MANY_OBJECTS"], skipped };
  for (const obj of objects) {
    if (!obj || typeof obj !== "object") { skipped++; continue; }
    const o = obj as Record<string, unknown>;
    if (o.type !== "indicator") { skipped++; continue; }
    if (typeof o.pattern !== "string" || typeof o.id !== "string") { skipped++; errors.push("STIX_INDICATOR_MALFORMED"); continue; }
    const extracted = extractPatternValue(o.pattern);
    if (!extracted) { skipped++; continue; }
    const type = STIX_TYPE_MAP[extracted.stixType];
    if (!type) { skipped++; continue; }
    const rawValue = extracted.stixType === "email-addr" ? (extracted.value.split("@")[1] ?? "") : extracted.value;
    const valueNormalized = normalizeIndicatorValue(type, rawValue);
    if (!valueNormalized) { skipped++; continue; }
    const refs = Array.isArray(o.external_references)
      ? (o.external_references as Array<Record<string, unknown>>).map((r) => String(r.url ?? r.source_name ?? "")).filter(Boolean).slice(0, 8)
      : [];
    indicators.push({
      type, valueNormalized,
      confidence: typeof o.confidence === "number" ? Math.max(0, Math.min(100, o.confidence)) : undefined,
      labels: Array.isArray(o.labels) ? (o.labels as unknown[]).filter((l): l is string => typeof l === "string").slice(0, 16) : [],
      validFrom: typeof o.valid_from === "string" ? o.valid_from : undefined,
      validUntil: typeof o.valid_until === "string" ? o.valid_until : undefined,
      externalReferences: refs,
      stixId: o.id,
    });
  }
  return { indicators, errors, skipped };
}
