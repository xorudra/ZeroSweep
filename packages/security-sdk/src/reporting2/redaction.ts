import { redactReportText } from "../unified/reporting";

/**
 * Prompt 37 §40/§90/§91: ReportRedactionService core.
 *
 * Two jobs:
 *  1. SCAN — find secret-shaped content in text destined for a client
 *     or a report and report it as redaction WARNINGS (kind + count
 *     only, never the value) so a reviewer sees them before
 *     finalization (§91).
 *  2. REDACT — produce the client-safe text. The base layer is the
 *     Prompt 20 report redactor (headers, bearer/basic, JSON/form/
 *     query secrets, PEM private keys); V2 adds cookie headers,
 *     standalone token shapes and personal-data (email) masking for
 *     client-facing surfaces.
 *
 * §71: bounded reproduction content only — dangerous payloads and
 * credentials are never carried into a client report, redacted or not;
 * the scan exists so a human can also REMOVE a section, not just mask.
 */
export interface RedactionFinding {
  kind: "PRIVATE_KEY" | "BEARER_TOKEN" | "COOKIE" | "PASSWORD_ASSIGNMENT" | "API_KEY" | "TOKEN" | "AWS_KEY" | "EMAIL";
  count: number;
}

const PATTERNS: { kind: RedactionFinding["kind"]; re: RegExp }[] = [
  { kind: "PRIVATE_KEY", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g },
  { kind: "BEARER_TOKEN", re: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g },
  { kind: "COOKIE", re: /\b(?:Set-Cookie|Cookie)\s*:\s*(?!\[REDACTED\])\S[^\r\n]*/gi },
  { kind: "PASSWORD_ASSIGNMENT", re: /\b(?:password|passwd|pwd)\s*[:=]\s*(?!\[REDACTED\])\S+/gi },
  { kind: "API_KEY", re: /\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*(?!\[REDACTED\])\S+/gi },
  { kind: "TOKEN", re: /\btoken\s*[:=]\s*(?!\[REDACTED\])\S+/gi },
  { kind: "AWS_KEY", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { kind: "EMAIL", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
];

export function scanForSecrets(text: string): RedactionFinding[] {
  if (!text) return [];
  const out: RedactionFinding[] = [];
  for (const { kind, re } of PATTERNS) {
    const matches = text.match(re);
    if (matches?.length) out.push({ kind, count: matches.length });
  }
  return out;
}

/** Client-safe text: Prompt 20 redaction + assignment/cookie/token/email layer. */
export function redactClientText(text: string): string {
  if (!text) return "";
  return redactReportText(text)
    .replace(/\b(?:Set-Cookie|Cookie)\s*:\s*[^\r\n]+/gi, (m) => `${m.split(":")[0]}: [REDACTED]`)
    .replace(/\b(password|passwd|pwd)\s*[:=]\s*\S+/gi, "$1: [REDACTED]")
    .replace(/\b(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+/gi, "$1: [REDACTED]")
    .replace(/\btoken\s*[:=]\s*\S+/gi, "token: [REDACTED]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED AWS KEY]")
    .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, "[REDACTED EMAIL]");
}

export interface RedactionPreview {
  warnings: { location: string; findings: RedactionFinding[] }[];
  totalFindings: number;
  clean: boolean;
}

/**
 * §91: scan every text surface of a report snapshot document and
 * report where a reviewer must look before finalizing. Operates on the
 * snapshot (already Prompt-20-redacted at build time) as a second,
 * independent check — defense in depth, and it catches secrets that
 * were introduced by manual report edits after generation.
 */
// Structural fields (ids, hashes, fingerprints) are identifiers, not
// prose: a SHA-256 content hash is not a leaked secret. The preview
// scans human-authored text; identifier subtrees are skipped so the
// document's own integrity fields never false-positive the §91 gate.
const STRUCTURAL_KEYS = new Set([
  "id", "contentHash", "artifactHash", "checksum", "fingerprint", "sourceFingerprint",
  "reportId", "snapshotId", "findingId", "workspaceId", "organizationId", "scanId",
  "assetId", "templateId", "sha256", "tokenHash",
]);
const HASH_SHAPED = /^([0-9a-f]{64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i;

export function redactionPreview(document: unknown): RedactionPreview {
  const warnings: RedactionPreview["warnings"] = [];
  const walk = (value: unknown, path: string) => {
    if (typeof value === "string") {
      if (HASH_SHAPED.test(value.trim())) return;
      const findings = scanForSecrets(value);
      if (findings.length) warnings.push({ location: path, findings });
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, `${path}[${i}]`));
    } else if (value && typeof value === "object") {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (STRUCTURAL_KEYS.has(k)) continue;
        walk(v, path ? `${path}.${k}` : k);
      }
    }
  };
  walk(document, "");
  const totalFindings = warnings.reduce((sum, w) => sum + w.findings.reduce((a, f) => a + f.count, 0), 0);
  return { warnings, totalFindings, clean: totalFindings === 0 };
}
