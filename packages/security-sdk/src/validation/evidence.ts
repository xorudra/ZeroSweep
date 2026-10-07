import { createHash } from "node:crypto";
import { capEvidence, redactEvidenceText } from "../vuln/redact";
import { canonicalStringify } from "./plan";
import type { ValidationEvidenceType, ValidationOutcome } from "./types";

/**
 * Validation evidence: sanitization, integrity and proof summaries
 * (Prompt 16 §33–§35, §61, §91). Evidence is sanitized BEFORE storage —
 * Authorization headers, cookies, tokens, API keys, passwords, private
 * keys, session IDs and cloud credentials are redacted automatically
 * (§34). The checksum (§35) covers the SANITIZED artifact, so integrity
 * verification never requires un-redacting anything.
 */

const SECRET_KEY_RE = /^(authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token|password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|session(?:[_-]?id)?|private[_-]?key|cloud[_-]?credentials?|aws[_-]?secret.*|client[_-]?secret)$/i;
const PEM_RE = /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
/** Free-text assignments the header/JSON redactors miss: "the password
 *  is hunter2", "token: abc", "token=abc" (§34 — redact where possible). */
const ASSIGNMENT_SECRET_RE = /\b(password|passwd|pwd|token|secret)(\s*(?:is|:|=)\s*)\S+/gi;
const MAX_EVIDENCE_BYTES = 64_000;

export function sanitizeEvidenceText(text: string): string {
  return redactEvidenceText(text)
    .replace(PEM_RE, "[REDACTED PRIVATE KEY]")
    .replace(AWS_KEY_RE, "[REDACTED AWS ACCESS KEY]")
    .replace(ASSIGNMENT_SECRET_RE, "$1$2[REDACTED]");
}

/** Deep-sanitize structured evidence: object keys that name secrets get
 *  their VALUES replaced wholesale (a token under an innocent-looking
 *  nested key is still a token); every string runs through the text
 *  redactor. Never throws on hostile input. */
export function sanitizeEvidenceValue(value: unknown, depth = 0): unknown {
  if (depth > 12) return "[TRUNCATED]";
  if (typeof value === "string") return sanitizeEvidenceText(value);
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => sanitizeEvidenceValue(v, depth + 1));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SECRET_KEY_RE.test(k) ? "[REDACTED]" : sanitizeEvidenceValue(v, depth + 1);
    }
    return out;
  }
  return value;
}

export interface SanitizedEvidence {
  type: ValidationEvidenceType;
  summary: string;
  content?: Record<string, unknown>;
  checksum: string;
  sourceTool?: string;
}

/** Build one stored evidence row: sanitize summary + content, cap size,
 *  and checksum the sanitized artifact (§34/§35). */
export function buildValidationEvidence(input: {
  type: ValidationEvidenceType;
  summary: string;
  content?: Record<string, unknown>;
  sourceTool?: string;
}): SanitizedEvidence {
  const summary = capEvidence(sanitizeEvidenceText(input.summary), 2000).text;
  const content = input.content ? (sanitizeEvidenceValue(input.content) as Record<string, unknown>) : undefined;
  let cappedContent: Record<string, unknown> | undefined;
  if (content) {
    const capped = capEvidence(JSON.stringify(content), MAX_EVIDENCE_BYTES);
    cappedContent = capped.truncated
      ? { truncated: true, preview: capped.text, checksumOfOriginal: capped.checksum }
      : (JSON.parse(capped.text) as Record<string, unknown>);
  }
  const checksum = createHash("sha256")
    .update(canonicalStringify({ type: input.type, summary, content: cappedContent ?? null }))
    .digest("hex");
  return {
    type: input.type,
    summary,
    ...(cappedContent ? { content: cappedContent } : {}),
    checksum,
    ...(input.sourceTool ? { sourceTool: input.sourceTool } : {}),
  };
}

/** §61: proof-of-validation summary — what was checked, when, which
 *  target, which safe method, the result, and evidence references. No
 *  sensitive raw data. */
export function buildProofOfValidation(input: {
  findingTitle: string;
  targetDescription: string;
  validatorName: string;
  validationType: string;
  startedAt: string;
  endedAt: string;
  outcome: ValidationOutcome;
  evidence: Array<{ type: string; checksum: string }>;
}): string {
  const lines = [
    `Proof of validation — ${sanitizeEvidenceText(input.findingTitle)}`,
    `Target: ${sanitizeEvidenceText(input.targetDescription)}`,
    `Method: ${input.validatorName} (${input.validationType}) — safe, non-destructive recheck`,
    `Window: ${input.startedAt} → ${input.endedAt}`,
    `Result: ${input.outcome}`,
    `Evidence: ${input.evidence.length > 0 ? input.evidence.map((e) => `${e.type}#${e.checksum.slice(0, 12)}`).join(", ") : "none"}`,
  ];
  return lines.join("\n");
}

/** §60: reporting classification — detection and validation stay
 *  distinguishable in every report. */
export type ReportValidationClass =
  | "SCANNER_DETECTED"
  | "SAFELY_VALIDATED"
  | "MANUALLY_VALIDATED"
  | "NOT_REPRODUCED"
  | "INCONCLUSIVE";

export function reportClassFor(input: {
  validationConfidence?: string | null;
  hasManualVerified?: boolean;
  lastOutcome?: string | null;
}): ReportValidationClass {
  if (input.hasManualVerified) return "MANUALLY_VALIDATED";
  if (input.validationConfidence === "VERIFIED") return "SAFELY_VALIDATED";
  if (input.lastOutcome === "NOT_REPRODUCED") return "NOT_REPRODUCED";
  if (input.validationConfidence === "INCONCLUSIVE" || input.lastOutcome === "INCONCLUSIVE") return "INCONCLUSIVE";
  return "SCANNER_DETECTED";
}
