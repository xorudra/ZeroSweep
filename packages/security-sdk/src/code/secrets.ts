import { createHash, createHmac } from "node:crypto";
import type { SecretType } from "./types";

/**
 * Secret handling (Prompt 12 §39–§44, §101). The platform NEVER stores,
 * displays or logs a raw secret value. At parse time the value is reduced
 * to: its TYPE, its file/line location, a one-way FINGERPRINT and — only
 * when safe — a redacted preview of first/last fragments. Every text
 * surface that might contain source (snippets, evidence, parser output)
 * is scrubbed through `redactSecretsInText` before storage or display.
 */

/**
 * High-signal secret VALUE patterns used for redaction + classification.
 * These exist to REMOVE values from text, never to extract them for use.
 */
export const SECRET_VALUE_PATTERNS: { type: SecretType; pattern: RegExp; label: string }[] = [
  { type: "CLOUD_CREDENTIAL", label: "AWS access key id", pattern: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g },
  { type: "CLOUD_CREDENTIAL", label: "AWS secret access key", pattern: /\baws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/gi },
  { type: "PRIVATE_KEY", label: "Private key block", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { type: "TOKEN", label: "GitHub token", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,255}\b/g },
  { type: "TOKEN", label: "Slack token", pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { type: "TOKEN", label: "JWT", pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { type: "API_KEY", label: "Stripe-style secret key", pattern: /\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { type: "API_KEY", label: "Generic API key assignment", pattern: /(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["'][^"'\s]{8,}["']/gi },
  { type: "PASSWORD", label: "Password assignment", pattern: /(?:password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{4,}["']/gi },
  { type: "DATABASE_CREDENTIAL", label: "Database URL with credentials", pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s/:@]+:[^\s/@]+@/gi },
];

const REDACTED = "[REDACTED]";

/** Replace every recognizable secret value in text with a marker. Used on
 *  snippets, evidence, parser messages and error text before ANY of them
 *  can reach storage, API responses or logs (§62/§101). */
export function redactSecretsInText(text: string): string {
  let out = text;
  for (const { pattern } of SECRET_VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    out = out.replace(pattern, REDACTED);
  }
  return out;
}

/** True when text still contains a recognizable raw secret value — the
 *  assertion tests use to prove redaction happened (§101). */
export function containsSecretValue(text: string): boolean {
  return SECRET_VALUE_PATTERNS.some(({ pattern }) => {
    pattern.lastIndex = 0;
    return pattern.test(text);
  });
}

/** Classify a detector/rule hit into a §42 secret type. Classification
 *  uses the detector name and rule id — never the secret value. */
export function classifySecretType(detector: string, ruleId?: string): SecretType {
  const hay = `${detector} ${ruleId ?? ""}`.toLowerCase();
  if (/private[-_ ]?key|rsa|openssh|pgp/.test(hay)) return "PRIVATE_KEY";
  if (/aws|azure|gcp|google|cloud|access[-_ ]?key[-_ ]?id/.test(hay)) return "CLOUD_CREDENTIAL";
  if (/database|postgres|mysql|mongo|jdbc|connection[-_ ]?string/.test(hay)) return "DATABASE_CREDENTIAL";
  if (/certificate|cert|tls|x509/.test(hay)) return "CERTIFICATE_SECRET";
  if (/password|passwd|credential/.test(hay)) return "PASSWORD";
  if (/jwt|bearer|oauth|session|token/.test(hay)) return "TOKEN";
  if (/api[-_ ]?key|apikey|secret[-_ ]?key|stripe|sendgrid|twilio/.test(hay)) return "API_KEY";
  return "GENERIC_SECRET";
}

/**
 * One-way secret fingerprints (§41). Keyed HMAC-SHA256 when the platform
 * secret-fingerprint key is configured (referenced by name, never stored
 * with findings); otherwise a domain-separated SHA-256. The raw secret
 * is an INPUT to the hash only — it is never a database key, never part
 * of the fingerprint output, and never retained.
 */
export class SecretFingerprintService {
  constructor(private readonly key?: string) {}

  fingerprint(secretValue: string): string {
    if (this.key) {
      return createHmac("sha256", this.key).update("dsrclone-secret-v1\0").update(secretValue).digest("hex");
    }
    return createHash("sha256").update("dsrclone-secret-v1\0").update(secretValue).digest("hex");
  }

  /** Constant-shape equality for dedupe checks without storing values. */
  matches(secretValue: string, fingerprint: string): boolean {
    return this.fingerprint(secretValue) === fingerprint;
  }
}

/**
 * Redacted preview (§39): `abcd…CRET`-style first/last fragments. Only
 * produced when the value is long enough that 4+4 fragments cannot
 * meaningfully reveal it; short values get NO preview at all.
 */
export function redactedPreview(secretValue: string): string | undefined {
  if (secretValue.length < 16) return undefined;
  const head = secretValue.slice(0, 4);
  const tail = secretValue.slice(-4);
  if (head === tail) return undefined;
  return `${head}…${tail}`;
}
