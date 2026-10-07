import { domainToASCII } from "node:url";

/**
 * Hostname + URL canonicalization and sensitive-data redaction for recon
 * results (Prompt 5 §19–§22). Everything a discovery tool prints passes
 * through here before it may become an asset, an endpoint or a log line:
 * tools emit untrusted-shaped data, and canonical form is what deduplication,
 * provenance merging and scope checks all compare.
 */

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Canonical hostname: lowercase, no trailing dot, IDN converted to punycode
 * (domainToASCII) so the same host in two representations can never become
 * two assets or slip past a scope rule. Returns null for malformed input —
 * wildcard records ("*.example.com"), underscores, empty labels, leading
 * digits-only TLD tricks and embedded credentials are all rejected.
 */
export function canonicalizeHostname(raw: string): string | null {
  if (typeof raw !== "string") return null;
  let host = raw.trim().toLowerCase();
  if (!host) return null;
  if (host.endsWith(".")) host = host.slice(0, -1);
  if (!host || host.includes("*") || host.includes("_") || host.includes("/") || host.includes("@")) return null;
  // IPv4 literals pass through when strictly valid.
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    const parts = host.split(".").map(Number);
    return parts.every((n) => n >= 0 && n <= 255) ? host : null;
  }
  let ascii = host;
  try { ascii = domainToASCII(host); } catch { return null; }
  if (!ascii || ascii.length > 253) return null;
  const labels = ascii.split(".");
  if (labels.length < 2) return null;
  if (!labels.every((l) => LABEL_RE.test(l))) return null;
  if (!/^[a-z]{2,}$/.test(labels[labels.length - 1]!)) return null;
  return ascii;
}

export function isValidHostname(raw: string): boolean {
  return canonicalizeHostname(raw) !== null;
}

/**
 * Canonical URL for inventory comparison (Prompt 5 §20): scheme + host
 * lowercased, default port removed, fragment dropped, duplicate slashes in
 * the path collapsed. The query string is preserved (minus sensitive values,
 * see redactUrl) and path case is kept — differently-cased or
 * differently-parameterised endpoints are semantically different and must
 * NOT be merged.
 */
export function canonicalizeUrl(raw: string): string | null {
  if (typeof raw !== "string" || !raw.trim()) return null;
  let u: URL;
  try { u = new URL(raw.trim()); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  if (u.username || u.password) return null; // embedded credentials: never inventory, never probe
  const host = canonicalizeHostname(u.hostname) ?? (u.hostname ? null : null);
  if (!host) return null;
  const isDefaultPort = (u.protocol === "https:" && (u.port === "" || u.port === "443")) || (u.protocol === "http:" && (u.port === "" || u.port === "80"));
  const port = isDefaultPort ? "" : `:${u.port}`;
  const path = u.pathname.replace(/\/{2,}/g, "/") || "/";
  return `${u.protocol}//${host}${port}${path}${u.search}`;
}

/** Parameter NAMES of a URL (Prompt 5 §21) — values are never stored. */
export function extractParameterNames(rawUrl: string): string[] {
  try {
    const u = new URL(rawUrl);
    return [...new Set([...u.searchParams.keys()])].sort();
  } catch {
    return [];
  }
}

const SENSITIVE_PARAMS = /^(token|access_token|refresh_token|api[-_]?key|apikey|secret|password|passwd|pwd|session|sessionid|sid|auth|authorization|jwt|signature|sig|key)$/i;
const EMAIL_RE = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
const BEARER_RE = /\b(Bearer|Basic)\s+[a-z0-9._~+/=-]{8,}/gi;
const LONG_SECRET_RE = /\b(?:sk|ghp|gho|AKIA)[-_a-z0-9]{12,}\b/g;

/**
 * Redact sensitive material from free text before it reaches logs, timeline
 * events or UI (Prompt 5 §22): emails, bearer/basic credentials and common
 * API-key shapes are masked. Authorized raw artifacts in object storage are
 * NOT passed through this — they stay intact behind access control.
 */
export function redactSensitiveText(text: string): string {
  return text
    .replace(EMAIL_RE, "[redacted-email]")
    .replace(BEARER_RE, "$1 [redacted]")
    .replace(LONG_SECRET_RE, "[redacted-secret]");
}

/**
 * Redact a URL for display/storage in ordinary inventory: values of
 * sensitive query parameters are masked; the parameter NAMES remain (they
 * are the inventory signal, §21).
 */
export function redactUrl(rawUrl: string): string {
  let u: URL;
  try { u = new URL(rawUrl); } catch { return rawUrl; }
  for (const key of [...u.searchParams.keys()]) {
    if (SENSITIVE_PARAMS.test(key)) u.searchParams.set(key, "REDACTED");
  }
  return u.toString();
}

export function isSensitiveParameter(name: string): boolean {
  return SENSITIVE_PARAMS.test(name);
}
