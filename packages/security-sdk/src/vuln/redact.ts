import { createHash } from "node:crypto";
import { redactUrl } from "../recon/normalize";

/**
 * Evidence safety (Prompt 7 §30/§31/§54/§55/§56). Scanner output is
 * UNTRUSTED, target-influenced content: before it is stored for ordinary
 * display it is redacted (credentials never survive), size-capped with a
 * checksum of the original, and stripped of active markup. Reference URLs
 * are validated to http/https so scanner output cannot inject
 * javascript:/data: links into the dashboard (§54).
 */

export const REDACTION = "[REDACTED]";

const HEADER_SECRET_RE = /^((?:authorization|cookie|set-cookie|x-api-key|x-auth-token|proxy-authorization)\s*:\s*).+$/gim;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi;
const BASIC_RE = /\bBasic\s+[A-Za-z0-9+/]+=*/gi;
const JSON_SECRET_RE = /("(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|session(?:[_-]?id)?)"\s*:\s*")[^"]*(")/gi;
const FORM_SECRET_RE = /\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|session(?:[_-]?id)?)=[^&\s;]+/gi;
const QUERY_SECRET_RE = /([?&](?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token|session(?:[_-]?id)?)=)[^&\s"']+/gi;

/** Redact credentials from evidence text (headers, bodies, URLs). The
 *  input is treated as hostile: this function never throws. */
export function redactEvidenceText(text: string): string {
  if (!text) return "";
  return text
    .replace(HEADER_SECRET_RE, `$1${REDACTION}`)
    .replace(BEARER_RE, `Bearer ${REDACTION}`)
    .replace(BASIC_RE, `Basic ${REDACTION}`)
    .replace(JSON_SECRET_RE, `$1${REDACTION}$2`)
    .replace(FORM_SECRET_RE, `$1=${REDACTION}`)
    .replace(QUERY_SECRET_RE, `$1${REDACTION}`);
}

export interface CappedEvidence {
  text: string;
  truncated: boolean;
  /** sha256 of the ORIGINAL (pre-truncation) text — the integrity link to
   *  the raw artifact kept in object storage (§31). */
  checksum: string;
  originalBytes: number;
}

/** Size-cap evidence with safe truncation (§31): the stored text is a
 *  prefix; the checksum + byte count preserve the link to the full raw
 *  artifact instead of silently discarding the remainder. */
export function capEvidence(text: string, maxBytes: number): CappedEvidence {
  const checksum = createHash("sha256").update(text).digest("hex");
  const originalBytes = Buffer.byteLength(text, "utf8");
  if (originalBytes <= maxBytes) return { text, truncated: false, checksum, originalBytes };
  let cut = text.slice(0, Math.max(0, maxBytes));
  // Never split a surrogate pair at the boundary.
  if (cut.length > 0 && /[\uD800-\uDBFF]$/.test(cut)) cut = cut.slice(0, -1);
  return { text: `${cut}\n…[truncated ${originalBytes - Buffer.byteLength(cut, "utf8")} bytes; full output in raw artifact ${checksum.slice(0, 12)}…]`, truncated: true, checksum, originalBytes };
}

/** Full evidence pipeline for one stored field: redact, then cap. */
export function prepareEvidence(text: string | undefined, maxBytes: number): { text?: string; truncated: boolean; checksum?: string } {
  if (text === undefined || text === "") return { truncated: false };
  const capped = capEvidence(redactEvidenceText(text), maxBytes);
  return { text: capped.text, truncated: capped.truncated, checksum: capped.checksum };
}

/** Escape ALL markup so stored text renders as inert text in the UI (§55).
 *  Evidence is displayed as text, never as HTML — defence in depth on top
 *  of the frontend's own escaping. */
export function escapeForDisplay(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Validate an external reference URL (§54): only absolute http/https URLs
 *  survive; anything else (javascript:, data:, protocol-relative, malformed)
 *  returns undefined so it can never become a dashboard link. */
export function sanitizeReferenceUrl(raw: unknown): string | undefined {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return undefined;
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return undefined;
    if (u.username || u.password) return undefined; // never carry credentials in a link
    return redactUrl(u.toString());
  } catch {
    return undefined;
  }
}

/** CSV export guard (§56): a cell starting with a formula prefix gets an
 *  apostrophe so spreadsheet apps treat it as text, not a formula. */
export function csvSafeCell(value: string): string {
  return /^[=+\-@\t\r]/.test(value) ? `'${value}` : value;
}
