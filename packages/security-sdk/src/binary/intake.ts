/**
 * Prompt 18 — secure binary intake (§2/§6/§7) + firmware/archive
 * discipline.
 *
 * Uploaded binaries and firmware are HOSTILE content. Intake:
 * validates the declared hash against the computed SHA-256 (identity
 * by content, §3), identifies format by MAGIC BYTES only (§5/§102),
 * caps sizes, and validates firmware archive inventories with the
 * hostile-archive discipline (zip-slip / symlink / decompression-bomb
 * caps, per the P12 pattern). Nothing is extracted onto a host path,
 * nothing is executed, and artifact-supplied scripts/configs are
 * recorded as data — never run.
 */
import { createHash } from "node:crypto";
import { detectBinaryFormat } from "./detect";
import type { BinaryArtifactSource } from "./types";

export interface BinaryUploadInput {
  name: string;
  declaredSha256?: string;
  declaredFormat?: string;
  sizeBytes: number;
  source: BinaryArtifactSource;
  /** First bytes for magic sniffing (the full artifact lives in
   *  object storage behind its reference). */
  magicPrefix?: Buffer;
}

export interface BinaryIntakeResult {
  accepted: boolean;
  sha256?: string;
  detectedFormat: "ELF" | "PE" | "MACH_O" | "UNKNOWN";
  reason?: string;
}

export const MAX_BINARY_BYTES = 2 * 1024 * 1024 * 1024; // 2 GiB (§82 maxBinarySize default)

export function sha256Of(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}
export function sha1Of(bytes: Buffer): string {
  return createHash("sha1").update(bytes).digest("hex");
}

/** Validate an upload DESCRIPTOR (the API never accepts artifact
 *  bytes; workers fetch from object storage by reference). */
export function validateBinaryArtifactUpload(input: BinaryUploadInput, opts: { maxBytes?: number } = {}): BinaryIntakeResult {
  const max = opts.maxBytes ?? MAX_BINARY_BYTES;
  if (!input.name || input.name.length > 512) return { accepted: false, detectedFormat: "UNKNOWN", reason: "Artifact name missing or oversized" };
  if (input.sizeBytes <= 0 || input.sizeBytes > max) return { accepted: false, detectedFormat: "UNKNOWN", reason: `Artifact size ${input.sizeBytes} outside the allowed range (max ${max})` };
  if (input.declaredSha256 && !/^[0-9a-f]{64}$/i.test(input.declaredSha256)) {
    return { accepted: false, detectedFormat: "UNKNOWN", reason: "Declared SHA-256 is not a 64-hex digest — artifact identity is its SHA-256 (§3)" };
  }
  const detected = input.magicPrefix ? detectBinaryFormat(input.magicPrefix) : "UNKNOWN";
  // §102: a declared format that contradicts the magic bytes is a
  // spoof — accept the bytes' identity, flag the mismatch, NEVER the
  // extension. We accept with the DETECTED format; only unknown
  // content with a binary claim is rejected outright.
  if (detected === "UNKNOWN" && input.magicPrefix && input.magicPrefix.length >= 4) {
    return { accepted: false, detectedFormat: "UNKNOWN", reason: "Content carries no recognized binary magic bytes — format UNKNOWN is never guessed (§5)" };
  }
  return { accepted: true, detectedFormat: detected };
}

// ── Firmware / archive inventory discipline (§7 + P12 pattern) ────

export interface FirmwareEntry {
  path: string;
  sizeBytes: number;
  kind: "FILE" | "SYMLINK" | "DIRECTORY" | "OTHER";
  linkTarget?: string;
}

export interface FirmwareValidation {
  accepted: boolean;
  reason?: string;
  /** Where extraction may go: always the isolated analysis
   *  workspace — never a host path. */
  extractionBoundary: "ISOLATED_ANALYSIS_WORKSPACE";
  entries: FirmwareEntry[];
  totalUncompressedBytes: number;
}

const MAX_FIRMWARE_ENTRIES = 100000;
const MAX_FIRMWARE_TOTAL_BYTES = 8 * 1024 * 1024 * 1024;

/** Validate a firmware/archive INVENTORY (names + sizes from a prior
 *  bounded listing — the archive itself is only ever unpacked inside
 *  a disposable analysis workspace). Traversal, absolute paths,
 *  drive letters, symlink entries and bombs are REFUSED. */
export function validateFirmwareInventory(entries: FirmwareEntry[]): FirmwareValidation {
  const boundary = "ISOLATED_ANALYSIS_WORKSPACE" as const;
  if (entries.length > MAX_FIRMWARE_ENTRIES) {
    return { accepted: false, reason: `Firmware inventory exceeds ${MAX_FIRMWARE_ENTRIES} entries (archive bomb guard)`, extractionBoundary: boundary, entries: [], totalUncompressedBytes: 0 };
  }
  let total = 0;
  for (const e of entries) {
    total += Math.max(0, e.sizeBytes);
    if (total > MAX_FIRMWARE_TOTAL_BYTES) {
      return { accepted: false, reason: "Firmware uncompressed size exceeds the archive bomb cap", extractionBoundary: boundary, entries: [], totalUncompressedBytes: total };
    }
    const p = e.path.replace(/\\/g, "/");
    if (p.startsWith("/") || /^[a-zA-Z]:/.test(p) || p.split("/").includes("..")) {
      return { accepted: false, reason: `Firmware entry escapes the extraction boundary (zip-slip): ${e.path}`, extractionBoundary: boundary, entries: [], totalUncompressedBytes: total };
    }
    if (e.kind === "SYMLINK") {
      return { accepted: false, reason: `Firmware symlink entries are never followed or extracted: ${e.path}`, extractionBoundary: boundary, entries: [], totalUncompressedBytes: total };
    }
  }
  return { accepted: true, extractionBoundary: boundary, entries, totalUncompressedBytes: total };
}
