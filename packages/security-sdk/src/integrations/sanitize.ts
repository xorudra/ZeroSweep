/**
 * Untrusted integration input sanitization (Prompt 24 §83, §114, §115,
 * §119). Repository names, branch names, commit messages, PR titles,
 * ticket text and chat content are ATTACKER-CONTROLLABLE data: they are
 * stored sanitized, rendered escaped, and NEVER interpolated into a
 * shell command, a query, or a template that executes (§84/§136).
 *
 * Sanitization strips terminal control sequences (ANSI escapes, C0/C1
 * controls, bidi overrides) so stored values cannot forge log lines or
 * corrupt terminal output, and caps length so a hostile payload cannot
 * bloat records.
 */

const ANSI_AND_CONTROL = new RegExp(
  // ESC sequences (CSI/OSC), C0 controls except \t, C1 controls, DEL,
  // and Unicode bidi/format overrides.
  "[\\u001b\\u009b][[\\]()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><~]|" +
  "[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f-\\u009f\\u202a-\\u202e\\u2066-\\u2069\\ufeff]",
  "g",
);

export function sanitizeUntrustedText(raw: unknown, maxLength = 500): string {
  if (raw === null || raw === undefined) return "";
  const text = String(raw).replace(ANSI_AND_CONTROL, "").replace(/\s+/g, " ").trim();
  return text.length > maxLength ? text.slice(0, maxLength) : text;
}

/** Branch names get the same treatment as titles (§115): shell
 *  metacharacters are harmless because the value is only ever data,
 *  but control characters are stripped and length is capped. */
export function sanitizeBranchName(raw: unknown): string {
  return sanitizeUntrustedText(raw, 255);
}

/** HTML-escape for any server-rendered surface (§114). The web UI
 *  renders through React (escaped by construction); this is for
 *  generated artifacts such as SARIF messages and ticket bodies. */
export function escapeHtmlText(raw: string): string {
  return raw
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Secret-pattern scrubber for outbound integration payloads (§42,
 * §50, §56, §119). Integration content is built from sanitized views
 * that never contain secret values in the first place; this scrubber
 * is the second line of defence for free-text fields (titles,
 * remediation guidance) that originated from tool output.
 */
const SECRET_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /AKIA[0-9A-Z]{16}/g, label: "AWS access key" },
  { re: /gh[pousr]_[A-Za-z0-9]{20,}/g, label: "GitHub token" },
  { re: /glpat-[A-Za-z0-9_-]{20,}/g, label: "GitLab token" },
  { re: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: "Slack token" },
  { re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, label: "private key" },
  { re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, label: "JWT" },
  { re: /\b(?:password|passwd|pwd|api[_-]?key|secret|token)\s*[:=]\s*[^\s"',;]{8,}/gi, label: "credential assignment" },
];

export function scrubSecretPatterns(text: string): { text: string; redactions: string[] } {
  let out = text;
  const redactions: string[] = [];
  for (const { re, label } of SECRET_PATTERNS) {
    out = out.replace(re, () => {
      redactions.push(label);
      return "[REDACTED]";
    });
  }
  return { text: out, redactions };
}

/** True when the scrubber changed the text — used by tests (§119) and
 *  by payload builders to record that a redaction occurred. */
export function containsSecretPattern(text: string): boolean {
  return SECRET_PATTERNS.some(({ re }) => {
    re.lastIndex = 0;
    return re.test(text);
  });
}
