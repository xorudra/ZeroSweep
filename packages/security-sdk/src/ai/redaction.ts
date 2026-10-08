import { redactEvidenceText, REDACTION } from "../vuln/redact";
import type { AiDataClassification } from "./types";
import { classificationRank } from "./types";

/**
 * AI context redaction (Prompt 21 §14/§15/§69). Everything that leaves
 * the platform toward a model provider passes through here FIRST.
 * Raw passwords, private keys, session cookies, API tokens, cloud
 * credentials, Wi-Fi credentials and authorization headers NEVER reach
 * an external provider (§14) — they are replaced with the platform
 * redaction marker, and the COUNT is returned for the request log
 * (§63) and the AI_CONTEXT_REDACTED audit event. Never throws on
 * hostile input.
 */

const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----|$)/g;
const AWS_KEY_RE = /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g;
const AWS_SECRET_RE = /\baws_secret_access_key\s*[:=]\s*[^\s"']+/gi;
const WIFI_PSK_RE = /\b(?:wifi|wpa|wireless)[_\-\s]?(?:psk|pass(?:word|phrase)?|key)\s*[:=]\s*[^\s"']+/gi;
const GENERIC_TOKEN_RE = /\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z\-_]{30,})\b/g;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

export interface RedactionResult {
  text: string;
  count: number;
}

function countOccurrences(haystack: string): number {
  if (!haystack) return 0;
  return haystack.split(REDACTION).length - 1;
}

export function redactForAi(text: string): RedactionResult {
  if (!text) return { text: "", count: 0 };
  const before = text;
  let out = redactEvidenceText(text);
  out = out
    .replace(PRIVATE_KEY_RE, REDACTION)
    .replace(AWS_SECRET_RE, `aws_secret_access_key=${REDACTION}`)
    .replace(AWS_KEY_RE, REDACTION)
    .replace(WIFI_PSK_RE, (m) => `${m.split(/[:=]/)[0]}=${REDACTION}`)
    .replace(GENERIC_TOKEN_RE, REDACTION)
    .replace(JWT_RE, REDACTION);
  // Count markers introduced by THIS pass (evidence storage may already
  // have redacted some; the request log counts what AI redaction did).
  return { text: out, count: Math.max(0, countOccurrences(out) - countOccurrences(before)) };
}

export interface ClassifiedField {
  key: string;
  value: string;
  classification: AiDataClassification;
}

/**
 * Field-level redaction: SECRET-classified fields are REMOVED entirely
 * (not merely masked) — a masked secret still leaks its shape/length,
 * and §14 is absolute for external providers. Other fields pass
 * through redactForAi.
 */
export function redactClassifiedFields(fields: ClassifiedField[]): { fields: ClassifiedField[]; count: number; removed: string[] } {
  let count = 0;
  const removed: string[] = [];
  const out: ClassifiedField[] = [];
  for (const f of fields) {
    if (classificationRank(f.classification) >= classificationRank("SECRET")) {
      removed.push(f.key);
      count += 1;
      continue;
    }
    const r = redactForAi(f.value);
    count += r.count;
    out.push({ ...f, value: r.text });
  }
  return { fields: out, count, removed };
}
