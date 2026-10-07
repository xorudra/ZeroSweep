import { redactEvidenceText } from "../vuln/redact";

/**
 * Import sanitization + bomb protection (Prompt 20 §51/§97/§98).
 *
 * EVERYTHING arriving from an external platform is untrusted: titles,
 * descriptions, evidence, HTML and metadata may carry script tags,
 * terminal escapes, oversized strings, malformed Unicode or fake URLs.
 * This module is the single funnel imported content passes through
 * before it is stored or rendered — safe normalization is the expected
 * outcome (§98), not rejection of the whole import.
 */

export const IMPORT_LIMITS = {
  maxRecords: 5_000,
  maxTitleLength: 512,
  maxDescriptionLength: 20_000,
  maxEvidenceLength: 50_000,
  maxFieldLength: 4_000,
  maxNestingDepth: 8,
} as const;

/** Strip markup carriers + control/terminal escapes, cap length. */
export function sanitizeImportedText(raw: unknown, maxLength: number = IMPORT_LIMITS.maxFieldLength): string {
  if (raw === null || raw === undefined) return "";
  let text = String(raw);
  // Drop malformed surrogate pairs instead of letting them break storage/rendering.
  text = text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, "�");
  // Remove HTML tags wholesale — imported HTML is never trusted markup (§51).
  text = text.replace(/<[^>]*>/g, " ");
  // Terminal escapes + C0/C1 controls (keeps \n and \t).
  // eslint-disable-next-line no-control-regex
  text = text.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "");
  // ANSI escape sequences that survived as printable ESC-less CSI remnants.
  text = text.replace(/\[[0-9;]*[A-Za-z]/g, (m) => (m.length <= 6 ? "" : m));
  return text.replace(/\s+\n/g, "\n").trim().slice(0, maxLength);
}

/** Escape for safe interpolation into generated HTML (§69). */
export function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Only http(s) URLs survive as references; everything else (javascript:,
 *  data:, file:, malformed) becomes undefined — fake URLs never render
 *  as links (§98). */
export function sanitizeImportedUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 2048) return undefined;
  try {
    const u = new URL(trimmed);
    if (u.protocol !== "https:" && u.protocol !== "http:") return undefined;
    return u.toString();
  } catch {
    return undefined;
  }
}

/** §63: imported evidence passes the platform redactor before storage. */
export function sanitizeImportedEvidence(raw: unknown): string {
  return redactEvidenceText(sanitizeImportedText(raw, IMPORT_LIMITS.maxEvidenceLength));
}

export interface ImportBombVerdict {
  ok: boolean;
  error?: string;
}

/** §97: structural limits enforced BEFORE any record is normalized. */
export function checkImportBounds(payload: unknown): ImportBombVerdict {
  const depth = (v: unknown, d: number): number => {
    if (d > IMPORT_LIMITS.maxNestingDepth + 2) return d;
    if (Array.isArray(v)) return v.reduce((m, x) => Math.max(m, depth(x, d + 1)), d);
    if (v && typeof v === "object") return Object.values(v).reduce((m, x) => Math.max(m, depth(x, d + 1)), d);
    return d;
  };
  if (depth(payload, 0) > IMPORT_LIMITS.maxNestingDepth) {
    return { ok: false, error: `import payload nesting exceeds ${IMPORT_LIMITS.maxNestingDepth} levels (§97)` };
  }
  const serialized = (() => { try { return JSON.stringify(payload)?.length ?? 0; } catch { return Number.MAX_SAFE_INTEGER; } })();
  if (serialized > 25_000_000) return { ok: false, error: "import payload exceeds 25 MB serialized bound (§97)" };
  return { ok: true };
}
