import { domainToASCII, domainToUnicode } from "node:url";
import { isIP } from "node:net";

/**
 * Asset normalization & deduplication identity (Prompt 29 §20–§24).
 * The canonical form is the deduplication key: equivalent spellings
 * of the same asset MUST collapse to one candidate, and the Unicode
 * representation is preserved alongside the ASCII form so IDN
 * differences stay visible (§21) instead of being silently merged.
 */

export interface NormalizedDomain {
  /** Canonical ASCII (punycode), lowercase, no trailing dot. */
  ascii: string;
  /** Unicode representation (may equal ascii for pure-ASCII names). */
  unicode: string;
  /** True when the name is an IDN (unicode ≠ ascii). */
  isIdn: boolean;
  /**
   * §21: suspicious normalization differences — mixed-script labels
   * or known confusable characters. A signal for human review,
   * never an accusation: legitimate IDNs exist.
   */
  suspiciousIdn: boolean;
}

const CONFUSABLE_RE = /[а-яА-Яα-ωΑ-Ω]/; // Cyrillic / Greek ranges commonly used in homographs
const SCRIPT_RES: Array<[string, RegExp]> = [
  ["latin", /[a-z]/],
  ["cyrillic", /[а-я]/],
  ["greek", /[α-ω]/],
  ["cjk", /[\u4e00-\u9fff]/],
  ["arabic", /[\u0600-\u06ff]/],
  ["hebrew", /[\u0590-\u05ff]/],
];

function labelScripts(label: string): Set<string> {
  const lower = label.toLowerCase();
  const found = new Set<string>();
  for (const [name, re] of SCRIPT_RES) if (re.test(lower)) found.add(name);
  return found;
}

export function normalizeDomain(input: string): NormalizedDomain | null {
  if (typeof input !== "string") return null;
  let raw = input.trim().toLowerCase();
  if (raw.endsWith(".")) raw = raw.slice(0, -1); // trailing dot (§131)
  if (!raw || raw.length > 253 || /[\s/\\@:]/.test(raw)) return null;
  let ascii: string;
  try {
    ascii = domainToASCII(raw);
  } catch {
    return null;
  }
  if (!ascii) return null;
  let unicode = raw;
  try {
    unicode = domainToUnicode(ascii) || raw;
  } catch {
    unicode = raw;
  }
  const isIdn = unicode !== ascii;
  let suspiciousIdn = false;
  if (isIdn || CONFUSABLE_RE.test(unicode)) {
    for (const label of unicode.split(".")) {
      const scripts = labelScripts(label);
      // Digits/hyphens are script-neutral; >1 real script in one label
      // is the classic homograph shape.
      if (scripts.size > 1) suspiciousIdn = true;
      if (scripts.has("latin") && (scripts.has("cyrillic") || scripts.has("greek"))) suspiciousIdn = true;
    }
  }
  return { ascii, unicode, isIdn, suspiciousIdn };
}

/** Canonical candidate identity for a domain (§22). */
export function domainIdentity(input: string): string | null {
  const n = normalizeDomain(input);
  return n ? n.ascii : null;
}

/** §23: normalize IPv4/IPv6 representations (compressed IPv6, no
 *  leading zeros in IPv4 octets); returns null for non-IPs. */
export function normalizeIp(input: string): string | null {
  if (typeof input !== "string") return null;
  const raw = input.trim().toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) {
    const octets = raw.split(".").map((o) => Number(o));
    if (octets.some((o) => o > 255)) return null;
    return octets.map((o) => String(o)).join(".");
  }
  const version = isIP(raw);
  if (version === 6) {
    // Expand then re-compress deterministically via URL parsing rules:
    // use the canonical form produced by parsing an IPv6 literal.
    const expanded = expandIpv6(raw);
    return expanded ? compressIpv6(expanded) : raw;
  }
  return null;
}

function expandIpv6(ip: string): string[] | null {
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0) return null;
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  return groups.map((g) => g.padStart(4, "0"));
}

function compressIpv6(groups: string[]): string {
  const trimmed = groups.map((g) => g.replace(/^0+(?=.)/, ""));
  // Find the longest run of "0" groups (length ≥ 2) to compress.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  trimmed.forEach((g, i) => {
    if (g === "0") {
      if (curStart === -1) curStart = i;
      curLen += 1;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  });
  if (bestLen < 2) return trimmed.join(":");
  const before = trimmed.slice(0, bestStart).join(":");
  const after = trimmed.slice(bestStart + bestLen).join(":");
  return `${before}::${after}`;
}

export interface NormalizedUrl {
  scheme: string;
  host: string;
  port: number | null;
  path: string;
  /** Canonical identity: scheme://host[:port]path (§24 — paths are
   *  NOT collapsed; different application paths stay different). */
  identity: string;
}

const DEFAULT_PORTS: Record<string, number> = { http: 80, https: 443, ws: 80, wss: 443 };

export function normalizeUrl(input: string): NormalizedUrl | null {
  if (typeof input !== "string" || input.length > 4096) return null;
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    return null;
  }
  const scheme = url.protocol.replace(/:$/, "").toLowerCase();
  if (scheme !== "http" && scheme !== "https" && scheme !== "ws" && scheme !== "wss") return null;
  const hostNorm = normalizeDomain(url.hostname) ?? (normalizeIp(url.hostname) ? { ascii: normalizeIp(url.hostname)! } : null);
  if (!hostNorm) return null;
  const host = hostNorm.ascii;
  let port: number | null = url.port ? Number(url.port) : null;
  if (port !== null && DEFAULT_PORTS[scheme] === port) port = null;
  const path = url.pathname === "" ? "/" : url.pathname;
  const identity = `${scheme}://${host}${port !== null ? `:${port}` : ""}${path}`;
  return { scheme, host, port, path, identity };
}

/** §20: certificate fingerprints normalize to lowercase hex, no separators. */
export function normalizeCertificateFingerprint(input: string): string | null {
  if (typeof input !== "string") return null;
  const hex = input.replace(/[^0-9a-fA-F]/g, "").toLowerCase();
  if (hex.length !== 40 && hex.length !== 64) return null; // SHA-1 / SHA-256
  return hex;
}

/** §20: technology names normalize for deduplication (case/spacing),
 *  preserving the observed display name separately at the call site. */
export function normalizeTechnologyName(input: string): string {
  return String(input ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}
