/**
 * Prompt 15 — directory input guards (§16/§99/§113–§115).
 *
 * Directory data is HOSTILE input: object names and attributes are
 * administrator- (and sometimes attacker-) controlled text that may
 * carry HTML, script strings, terminal escapes, invalid Unicode and
 * oversized values (§115). Everything the engine stores or displays
 * passes through sanitization; every value placed into an LDAP filter
 * is escaped (§16/§114); payloads are size/depth bounded like the
 * cloud engine's (§99 in P14). Credential-reference validation and
 * secret-shape detection are SHARED with the cloud engine — one
 * implementation, one discipline.
 */
import { sanitizeCloudText, sanitizeStringMap } from "../cloudsec/guards";

export { sanitizeCloudText, sanitizeStringMap };
export { isValidCredentialReference, looksLikeSecretValue, redactSecretShapes } from "../cloudsec/guards";

export const MAX_DIRECTORY_PAYLOAD_BYTES = 64 * 1024 * 1024; // 64 MiB artifact cap (§87 maxArtifactSize default)
export const MAX_DIRECTORY_JSON_DEPTH = 32;
export const MAX_DIRECTORY_OBJECTS = 500000; // hard ceiling (§87 caps)
export const MAX_ATTRIBUTE_STRING = 4096;

/** Escape a value for use inside an LDAP search filter (RFC 4515 §3):
 *  `*`, `(`, `)`, `\` and NUL are hex-escaped, so a value can NEVER
 *  change the filter's structure (§16/§114). Non-string input is
 *  coerced; control characters other than the escaped set are dropped. */
export function escapeLdapFilterValue(value: string): string {
  let out = "";
  for (const ch of String(value)) {
    const code = ch.charCodeAt(0);
    if (ch === "*") out += "\\2a";
    else if (ch === "(") out += "\\28";
    else if (ch === ")") out += "\\29";
    else if (ch === "\\") out += "\\5c";
    else if (code === 0) out += "\\00";
    else if (code < 0x20 || code === 0x7f) continue; // strip other controls (log-injection guard)
    else out += ch;
  }
  return out;
}

/** Escape a distinguished-name component value (RFC 4514): the DN
 *  specials plus leading/trailing space and leading `#`. */
export function escapeLdapDnValue(value: string): string {
  let out = "";
  const chars = [...String(value)];
  chars.forEach((ch, i) => {
    if (ch === "," || ch === "+" || ch === '"' || ch === "\\" || ch === "<" || ch === ">" || ch === ";" || ch === "=") out += `\\${ch}`;
    else if (ch === " " && (i === 0 || i === chars.length - 1)) out += "\\ ";
    else if (ch === "#" && i === 0) out += "\\#";
    else if (ch.charCodeAt(0) < 0x20) out += `\\${ch.charCodeAt(0).toString(16).padStart(2, "0")}`;
    else out += ch;
  });
  return out;
}

/** Sanitize one directory display string (§115): shared text hygiene
 *  (tags/escapes stripped, length-bounded) plus invalid-Unicode and
 *  bidi/control cleanup so stored values are safe in UI, logs and
 *  reports. */
export function sanitizeDirectoryText(value: unknown, maxLen = MAX_ATTRIBUTE_STRING): string {
  if (typeof value !== "string") return "";
  // Drop lone surrogates / replacement-worthy sequences before the
  // shared sanitizer bounds the length.
  const cleaned = value.replace(/[\uD800-\uDFFF]/g, "").replace(/\uFFFD/g, "");
  // Directory display strings additionally lose markup: object names
  // are administrator-controlled text rendered in graph/report UIs, so
  // tag sequences are removed at ingestion (§115) rather than relying
  // on every renderer to escape them.
  return sanitizeCloudText(cleaned, maxLen).replace(/<[^>]{0,200}>/g, "");
}

/** Bounded JSON parse for directory payloads (§16 oversized-response
 *  guard): byte cap + iterative depth check. Throws on violation —
 *  hostile payloads fail the import, never the process. */
export function parseBoundedDirectoryJson(text: string, opts: { maxBytes?: number; what?: string } = {}): unknown {
  const maxBytes = opts.maxBytes ?? MAX_DIRECTORY_PAYLOAD_BYTES;
  const what = opts.what ?? "directory payload";
  if (typeof text !== "string" || text.length === 0) throw new Error(`${what}: empty payload`);
  if (Buffer.byteLength(text, "utf8") > maxBytes) throw new Error(`${what}: payload exceeds ${maxBytes} bytes`);
  const parsed: unknown = JSON.parse(text);
  assertJsonDepth(parsed, MAX_DIRECTORY_JSON_DEPTH, what);
  return parsed;
}

function assertJsonDepth(value: unknown, maxDepth: number, what: string, depth = 0): void {
  if (depth > maxDepth) throw new Error(`${what}: JSON nesting exceeds depth ${maxDepth}`);
  if (Array.isArray(value)) {
    if (value.length > 200000) throw new Error(`${what}: array exceeds 200000 entries`);
    for (const v of value) assertJsonDepth(v, maxDepth, what, depth + 1);
  } else if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 10000) throw new Error(`${what}: object exceeds 10000 keys`);
    for (const [, v] of entries) assertJsonDepth(v, maxDepth, what, depth + 1);
  }
}

export function dirRec(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

export function dirArr(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.filter((x): x is Record<string, unknown> => x !== null && typeof x === "object") : [];
}

export function dirStr(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? sanitizeDirectoryText(v) : undefined;
}

export function dirBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

export function dirNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function dirStrList(v: unknown, cap = 512): string[] {
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === "string").map((x) => sanitizeDirectoryText(x, 512)).filter(Boolean).slice(0, cap);
}

/** A credential-shaped string detector specialized for directory
 *  payloads (§113): fixture/real passwords, hashes (NT/LM shapes) and
 *  ticket material must never survive normalization. Returns true when
 *  the value LOOKS like credential material. The engine drops such
 *  attribute values rather than storing them. */
export function looksLikeCredentialMaterial(value: string): boolean {
  if (typeof value !== "string") return false;
  const v = value.trim();
  if (/^[a-f0-9]{32}:[a-f0-9]{32}$/i.test(v)) return true; // LM:NT hash pair
  if (/^\$krb5(asrep|tgs)\$/i.test(v)) return true; // Kerberos ticket material
  if (/ntlm|nthash|lmhash/i.test(v) && v.length > 24) return true;
  return false;
}

/** Strip credential-material-shaped attribute values from a metadata
 *  record (§19/§113): string values under secret-shaped keys are
 *  removed, and any string that LOOKS like credential material is
 *  dropped whatever its key. Structural metadata whose key merely
 *  CONTAINS a password-related word — the password POLICY object,
 *  passwordLastSet timestamps, pwdNeverExpires flags — is posture
 *  metadata, not credential material, and is preserved. */
const SECRET_ATTRIBUTE_KEYS = /(password|passwd|pwd|hash|secret|ticket|credential|ntlm|token|privatekey)$/i;

export function stripCredentialMaterial(record: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(record)) {
    if (typeof value === "string" && (SECRET_ATTRIBUTE_KEYS.test(key) || looksLikeCredentialMaterial(value))) continue;
    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      out[key] = stripCredentialMaterial(value as Record<string, unknown>);
      continue;
    }
    out[key] = value;
  }
  return out;
}
