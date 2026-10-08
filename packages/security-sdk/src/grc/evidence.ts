import { createHash } from "node:crypto";
import type { EvidenceSnapshot } from "./types";

/**
 * Evidence integrity + hostile manual-upload defenses (Prompt 26
 * §20–§24, §40, §136). Evidence is snapshot-based and hashed at
 * collection time; later source changes cannot alter it (§21).
 */

/** Canonical JSON: recursively key-sorted so hashes are stable. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export function hashEvidence(snapshot: Record<string, unknown>): string {
  return createHash("sha256").update(canonicalJson(snapshot), "utf8").digest("hex");
}

export function hashContent(content: string | Buffer): string {
  return createHash("sha256").update(content).digest("hex");
}

export function snapshotEvidence(input: EvidenceSnapshot): EvidenceSnapshot & { hash: string } {
  return { ...input, hash: hashEvidence(input.snapshot) };
}

export function verifyEvidenceHash(snapshot: Record<string, unknown>, expectedHash: string): boolean {
  return hashEvidence(snapshot) === expectedHash;
}

/* ----------------------- hostile upload defenses ----------------------- */

export const MAX_MANUAL_EVIDENCE_BYTES = 10 * 1024 * 1024; // 10 MiB (§40)

const ALLOWED_CONTENT_TYPES = new Map<string, string[]>([
  ["application/pdf", ["%PDF-"]],
  ["image/png", ["\x89PNG"]],
  ["image/jpeg", ["\xff\xd8\xff"]],
  ["text/plain", []],
  ["text/csv", []],
  ["application/json", []],
]);

const ARCHIVE_SIGNATURES = ["PK\x03\x04", "Rar!", "\x1f\x8b", "7z\xbc\xaf\x27\x1c", "BZh"];

export interface UploadValidation {
  accepted: boolean;
  reasons: string[];
  /** Stored-XSS-safe rendering of the filename (§40). */
  safeFilename: string;
  detectedType: string | null;
}

/** Sanitize a filename: strip path traversal, control chars and any
 *  markup; the result is safe to store and display. */
export function sanitizeFilename(name: string): string {
  const base = name.split(/[\\/]/).pop() ?? "evidence";
  const cleaned = base
    // eslint-disable-next-line no-control-regex -- stripping control chars IS the sanitization
    .replace(/[<>:"/\\|?*\u0000-\u001f\u007f]/g, "_")
    .replace(/^\.+/, "")
    .slice(0, 120);
  return cleaned || "evidence";
}

export function validateManualEvidenceUpload(input: {
  filename: string;
  contentType: string;
  content: Buffer;
}): UploadValidation {
  const reasons: string[] = [];
  const safeFilename = sanitizeFilename(input.filename);
  if (input.content.length === 0) reasons.push("empty file rejected");
  if (input.content.length > MAX_MANUAL_EVIDENCE_BYTES) {
    reasons.push(`file exceeds the ${MAX_MANUAL_EVIDENCE_BYTES}-byte manual-evidence limit (§40)`);
  }
  const head = input.content.subarray(0, 8).toString("latin1");
  for (const sig of ARCHIVE_SIGNATURES) {
    if (head.startsWith(sig)) {
      reasons.push("archive containers are not accepted as manual evidence (archive-bomb defense, §40)");
      break;
    }
  }
  const allowed = ALLOWED_CONTENT_TYPES.get(input.contentType);
  let detectedType: string | null = null;
  if (!allowed) {
    reasons.push(`content type ${input.contentType} is not in the manual-evidence allowlist (§39/§40)`);
  } else {
    if (input.contentType === "application/pdf") detectedType = head.startsWith("%PDF-") ? "application/pdf" : null;
    else if (input.contentType === "image/png") detectedType = head.startsWith("\x89PNG") ? "image/png" : null;
    else if (input.contentType === "image/jpeg") detectedType = head.startsWith("\xff\xd8\xff") ? "image/jpeg" : null;
    else detectedType = input.contentType;
    if (detectedType === null) {
      reasons.push(`content does not match declared content type ${input.contentType} (content-type mismatch, §40)`);
    }
  }
  // HTML/script payloads are never accepted as evidence files (§136):
  // a document whose body is markup is rejected, not stored.
  const text = input.content.subarray(0, 2048).toString("utf8").trimStart().toLowerCase();
  if (text.startsWith("<!doctype html") || text.startsWith("<html") || text.startsWith("<script")) {
    reasons.push("HTML/script content is not accepted as evidence (stored-XSS defense, §40)");
  }
  return { accepted: reasons.length === 0, reasons, safeFilename, detectedType };
}

/** Escape a free-text evidence note for safe HTML rendering contexts. */
export function escapeEvidenceText(text: string): string {
  return text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
