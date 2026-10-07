/**
 * Prompt 13 — hostile metadata discipline (§60/§109).
 *
 * Image metadata, Kubernetes labels/annotations, workload names and
 * runtime-event fields are ATTACKER-CONTROLLED text: they can carry
 * terminal escapes, bidirectional overrides, script-like content, log
 * forgeries and secret values. Everything stored or displayed passes
 * through here first: control characters stripped, secrets redacted
 * (Prompt 12 patterns), lengths capped. Sanitization NEVER silently
 * "cleans" identity fields used for correlation — those are validated
 * separately and rejected when malformed.
 */
import { redactSecretsInText } from "../code/secrets";
import { redactEvidenceText } from "../vuln/redact";

/** Strip ANSI/terminal escapes, C0/C1 controls and bidi overrides. */
export function stripControlCharacters(text: string): string {
  return text
    // eslint-disable-next-line no-control-regex
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, "") // CSI sequences
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, "")
    .replace(/[\u202a-\u202e\u2066-\u2069]/g, "") // bidi overrides
    .replace(/\r\n?/g, "\n");
}

/** Sanitize one untrusted text field for storage/display (§60/§109). */
export function sanitizeCloudText(value: unknown, maxLength = 500): string {
  if (value === null || value === undefined) return "";
  const raw = typeof value === "string" ? value : String(value);
  const cleaned = redactSecretsInText(redactEvidenceText(stripControlCharacters(raw))).trim();
  return cleaned.length > maxLength ? `${cleaned.slice(0, maxLength)}…[truncated]` : cleaned;
}

/** Sanitize a string map (labels/annotations/event fields), capping the
 *  entry count, key/value lengths and dropping empties. */
export function sanitizeStringMap(input: unknown, opts: { maxEntries?: number; maxKey?: number; maxValue?: number } = {}): Record<string, string> {
  const out: Record<string, string> = {};
  if (!input || typeof input !== "object") return out;
  const maxEntries = opts.maxEntries ?? 50;
  let count = 0;
  for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
    if (count >= maxEntries) break;
    const key = sanitizeCloudText(k, opts.maxKey ?? 200);
    if (!key) continue;
    // Map values are single-line fields (labels, annotations, event
    // fields): embedded newlines are the log-injection vector (§60).
    out[key] = sanitizeCloudText(v, opts.maxValue ?? 500).replace(/\n/g, " ");
    count++;
  }
  return out;
}

/** Kubernetes identifier validation (§35/§109): names, namespaces,
 *  kinds are identity — malformed values are rejected, never sanitized
 *  into a different identity. DNS-subdomain / label-value shapes only. */
const K8S_NAME_RE = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/;
export function isValidKubernetesName(value: string, maxLength = 253): boolean {
  return value.length > 0 && value.length <= maxLength && K8S_NAME_RE.test(value);
}

/** Shell/terminal metacharacters that must never appear in a stored
 *  process name or subject reference (§60). */
export function containsHostileCharacters(value: string): boolean {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f]/.test(value) || value.includes("\u001b");
}
