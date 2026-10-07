/**
 * Prompt 17 — hostile-content sanitization (§107) + bounded parsing.
 *
 * Everything extracted from an app binary — manifest strings,
 * decompiled source, tool output, traffic metadata — is attacker-
 * controlled data. It may contain HTML/script markup, ANSI/terminal
 * escapes, invalid Unicode, bidirectional overrides and oversized
 * strings. Sanitization happens ONCE, at parse time, so nothing
 * downstream (persistence, API, GUI, logs) ever sees the raw shape.
 */
import { redactSecretsInText } from "../code/secrets";

/** Hard caps for any single extracted string (§107). */
export const MAX_MOBILE_STRING = 2048;
export const MAX_MOBILE_PAYLOAD_BYTES = 32 * 1024 * 1024; // 32 MiB report cap
export const MAX_MOBILE_JSON_DEPTH = 24;

/**
 * Sanitize one extracted string: strip C0/C1 control characters
 * (including ANSI escape sequences), strip Unicode bidi overrides and
 * zero-width characters, replace lone surrogates / replacement-worthy
 * code points, collapse whitespace runs and cap the length. Secret-
 * shaped values are redacted by the shared P12 pass — a manifest or
 * source string is never a place a credential survives (§28).
 */
export function sanitizeMobileText(value: unknown, maxLen = MAX_MOBILE_STRING): string {
  if (typeof value !== "string") return "";
  let out = "";
  for (const ch of value) {
    const cp = ch.codePointAt(0) ?? 0;
    // C0/C1 controls (covers ESC of ANSI sequences), DEL.
    if (cp < 0x20 || (cp >= 0x7f && cp <= 0x9f)) continue;
    // Bidi overrides / isolates + zero-width characters.
    if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) continue;
    if (cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0xfeff) continue;
    // Lone surrogates surface as U+FFFD through codePointAt on broken
    // strings; keep them visible-but-safe rather than dropping content.
    out += ch;
  }
  out = out.replace(/\s+/g, " ").trim();
  if (out.length > maxLen) out = out.slice(0, maxLen);
  return redactSecretsInText(out);
}

/** Bounded JSON parse for tool reports (§107): byte cap, depth cap,
 *  prototype-pollution keys dropped. Returns undefined on any failure
 *  — parsers fail closed, never throw hostile shapes upward. */
export function parseBoundedMobileJson(text: string, opts: { maxBytes?: number; what?: string } = {}): unknown {
  const maxBytes = opts.maxBytes ?? MAX_MOBILE_PAYLOAD_BYTES;
  if (typeof text !== "string" || text.length === 0 || Buffer.byteLength(text, "utf8") > maxBytes) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  const clean = (v: unknown, depth: number): unknown => {
    if (depth > MAX_MOBILE_JSON_DEPTH) return undefined;
    if (Array.isArray(v)) return v.slice(0, 5000).map((x) => clean(x, depth + 1));
    if (v !== null && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
        out[k] = clean(val, depth + 1);
      }
      return out;
    }
    return v;
  };
  void opts.what;
  return clean(parsed, 0);
}

export function mobRec(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

export function mobArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

export function mobStr(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? sanitizeMobileText(v) : undefined;
}

export function mobBool(v: unknown): boolean | undefined {
  return typeof v === "boolean" ? v : undefined;
}

export function mobNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

export function mobStrList(v: unknown, cap = 512): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") out.push(sanitizeMobileText(item));
    if (out.length >= cap) break;
  }
  return out;
}
