/**
 * Banner sanitization (Prompt 10 §36/§75). Service banners are UNTRUSTED
 * content: they may carry HTML (stored XSS), terminal escape sequences,
 * control characters and log-injection payloads, and they may be huge.
 * Every banner passes through here BEFORE storage or display: control
 * characters and escape sequences are stripped, markup is neutralized,
 * and the result is size-capped.
 */

export const MAX_BANNER_LENGTH = 512;

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
// eslint-disable-next-line no-control-regex
const ESCAPE_SEQUENCES = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007]*(\u0007|\u001b\\)|\u001b[@-Z\\-_]/g;

export function sanitizeBanner(raw: string | undefined, maxLength = MAX_BANNER_LENGTH): string | undefined {
  if (!raw) return undefined;
  let out = raw.replace(ESCAPE_SEQUENCES, "").replace(CONTROL_CHARS, " ");
  // Neutralize markup so a banner can never become stored HTML/JS.
  out = out.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  out = out.replace(/\s+/g, " ").trim();
  if (!out) return undefined;
  return out.length > maxLength ? `${out.slice(0, maxLength)}…` : out;
}

/** Sanitize free-text evidence/observation text from scanner output with
 *  the same rules (larger cap — evidence is longer-form than banners). */
export function sanitizeScannerText(raw: string | undefined, maxLength = 4096): string {
  if (!raw) return "";
  let out = raw.replace(ESCAPE_SEQUENCES, "").replace(CONTROL_CHARS, " ");
  out = out.replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return out.length > maxLength ? out.slice(0, maxLength) : out;
}
