/**
 * Prompt 18 — string extraction + classification (§28–§32).
 *
 * Extraction is bounded (ScanBudget maxStrings) and reads bytes
 * only — strings are DATA, never executed, never evaluated. Every
 * string is sanitized at extraction time (hostile strings carry
 * HTML, terminal escapes and invalid Unicode, §104) and secret-shaped
 * values are redacted by the shared P12 pass. SECRET_CANDIDATEs carry
 * a one-way HMAC fingerprint instead of the value (§30): the raw
 * candidate never leaves this function.
 */
import { createHmac } from "node:crypto";
import { SECRET_VALUE_PATTERNS, redactSecretsInText } from "../code/secrets";
import { sanitizeMobileText } from "../mobile/sanitize";
import type { BinaryStringCategory, NormalizedBinaryString } from "../findings/finding.types";

const URL_RE = /\bhttps?:\/\/[^\s"'<>\\]{3,200}/i;
const DOMAIN_RE = /\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|cloud|internal|local|invalid|example|test)\b/i;
const WIN_PATH_RE = /\b[A-Za-z]:\\(?:[^\\/:*?"<>|\s]+\\)*[^\\/:*?"<>|\s]*/;
const UNIX_PATH_RE = /(?:^|\s)(\/(?:[a-z0-9._-]+\/)+[a-z0-9._-]*)/i;
const REGISTRY_RE = /\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\/i;
const CRYPTO_RE = /\b(?:MD5|SHA-?1|SHA-?256|SHA-?512|AES|DES|3DES|RC4|ECB|CBC|PKCS|OpenSSL|BCrypt|CryptAcquireContext|EVP_|CCCrypt)\b/i;
const ERROR_RE = /\b(?:error|failed|exception|invalid|denied|warning|fatal|assert)\b/i;

function secretFingerprint(value: string): string {
  return createHmac("sha256", "zerosweep-binary-secret-fingerprint").update(value).digest("hex").slice(0, 24);
}

function classify(value: string): { category: BinaryStringCategory; secretType?: string } {
  for (const { type, pattern } of SECRET_VALUE_PATTERNS) {
    if (pattern.test(value)) return { category: "SECRET_CANDIDATE", secretType: type };
  }
  if (/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/.test(value)) {
    return { category: "SECRET_CANDIDATE", secretType: "PRIVATE_KEY_MATERIAL" };
  }
  if (URL_RE.test(value)) return { category: "URL" };
  if (REGISTRY_RE.test(value)) return { category: "REGISTRY_PATH" };
  if (CRYPTO_RE.test(value)) return { category: "CRYPTO_REFERENCE" };
  if (DOMAIN_RE.test(value)) return { category: "DOMAIN" };
  if (WIN_PATH_RE.test(value) || UNIX_PATH_RE.test(value)) return { category: "FILE_PATH" };
  if (ERROR_RE.test(value)) return { category: "ERROR_MESSAGE" };
  return { category: "GENERIC" };
}

export interface ExtractedStrings {
  strings: NormalizedBinaryString[];
  summary: { total: number; byCategory: Record<string, number> };
  discoveredReferences: { value: string; kind: "URL" | "DOMAIN"; classification: "DISCOVERED_REFERENCE" }[];
}

/** ASCII + UTF-16LE printable runs, bounded. Pure byte reading. */
export function extractBinaryStrings(bytes: Buffer, opts: { maxStrings?: number; sectionOf?: (offset: number) => string | undefined; source: string }): ExtractedStrings {
  const max = opts.maxStrings ?? 5000;
  const out: NormalizedBinaryString[] = [];
  const byCategory: Record<string, number> = {};
  const refs: ExtractedStrings["discoveredReferences"] = [];
  let total = 0;
  const seenRefs = new Set<string>();

  const consider = (raw: string, encoding: NormalizedBinaryString["encoding"], offset: number) => {
    if (raw.length < 4 || raw.length > 4096) return;
    total++;
    const { category, secretType } = classify(raw);
    byCategory[category] = (byCategory[category] ?? 0) + 1;
    const urlMatch = raw.match(URL_RE);
    const domMatch = !urlMatch ? raw.match(DOMAIN_RE) : null;
    const refValue = urlMatch?.[0] ?? domMatch?.[0];
    if ((category === "URL" || category === "DOMAIN") && refValue) {
      const clean = sanitizeMobileText(refValue, 300);
      if (clean && !seenRefs.has(clean)) {
        seenRefs.add(clean);
        // §31: DISCOVERED_REFERENCE — never a target, never scope.
        refs.push({ value: clean, kind: category === "URL" ? "URL" : "DOMAIN", classification: "DISCOVERED_REFERENCE" });
      }
    }
    if (out.length >= max) return;
    if (category === "SECRET_CANDIDATE") {
      // §30: value NEVER persists — fingerprint + redacted preview only.
      out.push({
        value: "[REDACTED SECRET CANDIDATE]",
        encoding, category, source: opts.source,
        secretFingerprint: secretFingerprint(raw),
        ...(secretType ? { secretType } : {}),
        redactedPreview: `${raw.slice(0, 2)}•••${raw.slice(-2)}`,
        ...(opts.sectionOf?.(offset) ? { location: opts.sectionOf(offset)! } : {}),
      });
      return;
    }
    out.push({
      value: sanitizeMobileText(redactSecretsInText(raw), 2048),
      encoding, category, source: opts.source,
      ...(opts.sectionOf?.(offset) ? { location: opts.sectionOf(offset)! } : {}),
    });
  };

  // ASCII runs.
  let start = -1;
  for (let i = 0; i <= bytes.length; i++) {
    const b = i < bytes.length ? bytes[i]! : 0;
    const printable = b >= 0x20 && b < 0x7f;
    if (printable && start === -1) start = i;
    if (!printable && start !== -1) {
      if (i - start >= 4) consider(bytes.toString("latin1", start, i), "ASCII", start);
      start = -1;
    }
  }
  // UTF-16LE runs.
  start = -1;
  for (let i = 0; i + 1 <= bytes.length; i += 2) {
    const lo = bytes[i]!, hi = bytes[i + 1]!;
    const printable = hi === 0 && lo >= 0x20 && lo < 0x7f;
    if (printable && start === -1) start = i;
    if (!printable && start !== -1) {
      if ((i - start) / 2 >= 4) consider(bytes.toString("utf16le", start, i), "UTF16LE", start);
      start = -1;
    }
  }
  return { strings: out, summary: { total, byCategory }, discoveredReferences: refs };
}
