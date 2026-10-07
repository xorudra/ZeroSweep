import { redactSecretsInText } from "./secrets";

/**
 * Repository path safety (Prompt 12 §60, §106, §107). Source findings may
 * only ever reference REPOSITORY-RELATIVE paths. Tool output is hostile:
 * absolute paths, traversal segments, control characters and ANSI escape
 * sequences are stripped or rejected before a path can be stored or
 * displayed. A path that cannot be proven to stay inside the repository
 * is REJECTED (null), never "fixed up" into a different meaning.
 */

/**
 * Normalize an untrusted path to a safe repository-relative path.
 * Returns null when the path is absolute, escapes the root via `..`,
 * contains NUL/control characters, or is empty.
 */
export function normalizeRepoPath(input: string): string | null {
  if (typeof input !== "string" || input.length === 0 || input.length > 1024) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(input)) return null;
  let p = input.replace(/\\/g, "/");
  // Strip URI-ish prefixes tools sometimes emit (file://, jar:file:...!).
  p = p.replace(/^file:\/+/i, "").replace(/^jar:file:[^!]*!/i, "");
  if (/^[a-zA-Z]:\//.test(p)) return null; // Windows drive-absolute
  if (p.startsWith("/")) return null; // POSIX-absolute
  const parts: string[] = [];
  for (const segment of p.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (parts.length === 0) return null; // escapes the repository root
      parts.pop();
      continue;
    }
    parts.push(segment);
  }
  if (parts.length === 0) return null;
  return parts.join("/");
}

/** True when `candidate` (already normalized) stays inside `root`. */
export function isWithinRoot(root: string, candidate: string): boolean {
  const r = normalizeRepoPath(root);
  const c = normalizeRepoPath(candidate);
  if (!r || !c) return false;
  return c === r || c.startsWith(`${r}/`);
}

/** Strip ANSI escapes + control characters for hostile display (§107). */
export function sanitizeDisplayText(text: string, maxLength = 2000): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u001b\[[0-9;]*[a-zA-Z]/g, "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").slice(0, maxLength);
}

/**
 * Minimal redacted code snippet (§61/§62): at most `contextLines` around
 * the finding, hard character cap, secret values redacted, display
 * sanitized. Snippets are evidence CONTEXT, never source dumps.
 */
export function buildRedactedSnippet(
  source: string | undefined,
  startLine: number | undefined,
  opts: { contextLines?: number; maxChars?: number } = {},
): string | undefined {
  if (!source) return undefined;
  const context = opts.contextLines ?? 2;
  const maxChars = opts.maxChars ?? 600;
  const lines = source.split(/\r?\n/);
  let slice = lines;
  if (startLine !== undefined && startLine >= 1) {
    const from = Math.max(0, startLine - 1 - context);
    const to = Math.min(lines.length, startLine + context);
    slice = lines.slice(from, to);
  } else {
    slice = lines.slice(0, context * 2 + 1);
  }
  const joined = slice.join("\n");
  return sanitizeDisplayText(redactSecretsInText(joined), maxChars);
}
