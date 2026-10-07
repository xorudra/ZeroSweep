import { normalizeRepoPath } from "./paths";
import type { SourceScanBudget } from "./types";

/**
 * Archive safety (Prompt 12 §9, §106). Uploaded archives are hostile
 * input. Before ANY extraction, the central directory is validated:
 * traversal entries (zip-slip), absolute paths, symlink entries,
 * excessive file counts, oversize totals and decompression bombs are
 * REJECTED — the archive is refused as a whole, never partially trusted.
 * Extraction (on source workers) additionally writes through the same
 * normalized-path checks; this module is the gate both paths share.
 */

export interface ArchiveEntry {
  name: string;
  uncompressedSize: number;
  compressedSize: number;
  isDirectory: boolean;
  /** Unix file-type bits (from external attributes) when present. */
  unixMode?: number;
  isSymlink: boolean;
}

export interface ArchiveValidation {
  ok: boolean;
  entries: ArchiveEntry[];
  errors: string[];
  totalUncompressedBytes: number;
}

const ARCHIVE_EXTENSIONS = [".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z", ".jar", ".war", ".gz", ".bz2", ".xz"];
const MAX_COMPRESSION_RATIO = 100;

function isArchiveName(name: string): boolean {
  const lower = name.toLowerCase();
  return ARCHIVE_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/** Validate an entry listing (any archive format) against §9 rules. */
export function validateArchiveEntries(
  entries: ArchiveEntry[],
  budget: SourceScanBudget,
): ArchiveValidation {
  const errors: string[] = [];
  let total = 0;
  if (entries.length > budget.maxFiles) {
    errors.push(`archive holds ${entries.length} entries — exceeds the ${budget.maxFiles}-file budget (§9)`);
  }
  for (const entry of entries) {
    total += Math.max(0, entry.uncompressedSize);
    const normalized = normalizeRepoPath(entry.name);
    if (normalized === null) {
      errors.push(`entry path escapes the archive root or is absolute: ${JSON.stringify(entry.name.slice(0, 80))}`);
    }
    if (entry.isSymlink) {
      errors.push(`symlink entries are never extracted: ${JSON.stringify(entry.name.slice(0, 80))}`);
    }
    if (entry.uncompressedSize > budget.maxFileSizeMb * 1024 * 1024) {
      errors.push(`entry exceeds the per-file size budget: ${JSON.stringify(entry.name.slice(0, 80))}`);
    }
    if (!entry.isDirectory && isArchiveName(entry.name)) {
      errors.push(`nested archives are rejected (depth limit 0): ${JSON.stringify(entry.name.slice(0, 80))}`);
    }
    if (entry.uncompressedSize > 1024 * 1024 && entry.compressedSize > 0) {
      const ratio = entry.uncompressedSize / entry.compressedSize;
      if (ratio > MAX_COMPRESSION_RATIO) {
        errors.push(`entry compression ratio ${Math.round(ratio)}:1 exceeds the bomb threshold: ${JSON.stringify(entry.name.slice(0, 80))}`);
      }
    }
  }
  if (total > budget.maxArchiveSizeMb * 1024 * 1024) {
    errors.push(`archive expands to ${total} bytes — exceeds the ${budget.maxArchiveSizeMb}MB archive budget (§9)`);
  }
  return { ok: errors.length === 0, entries, errors, totalUncompressedBytes: total };
}

/**
 * Parse a ZIP central directory WITHOUT extracting anything (no
 * decompression, no writes). Malformed/hostile structures fail closed.
 */
export function readZipCentralDirectory(bytes: Uint8Array): { entries: ArchiveEntry[] } | { error: string } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Find the End Of Central Directory record (search the tail window).
  let eocd = -1;
  const tail = Math.max(0, bytes.length - 65557);
  for (let i = bytes.length - 22; i >= tail; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return { error: "not a ZIP archive (no end-of-central-directory record)" };
  const count = view.getUint16(eocd + 10, true);
  let offset = view.getUint32(eocd + 16, true);
  const entries: ArchiveEntry[] = [];
  const decoder = new TextDecoder("utf-8", { fatal: false });
  for (let n = 0; n < count; n++) {
    if (offset + 46 > bytes.length || view.getUint32(offset, true) !== 0x02014b50) {
      return { error: "corrupt ZIP central directory" };
    }
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const nameLen = view.getUint16(offset + 28, true);
    const extraLen = view.getUint16(offset + 30, true);
    const commentLen = view.getUint16(offset + 32, true);
    const externalAttrs = view.getUint32(offset + 38, true);
    const nameBytes = bytes.subarray(offset + 46, offset + 46 + nameLen);
    if (nameBytes.length !== nameLen) return { error: "truncated ZIP central directory" };
    const name = decoder.decode(nameBytes);
    const unixMode = externalAttrs >>> 16;
    const fileType = unixMode & 0o170000;
    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      isDirectory: name.endsWith("/"),
      unixMode: unixMode || undefined,
      isSymlink: fileType === 0o120000,
    });
    offset += 46 + nameLen + extraLen + commentLen;
  }
  return { entries };
}

/** Validate raw ZIP bytes end-to-end (§9/§106). */
export function validateZipArchive(bytes: Uint8Array, budget: SourceScanBudget): ArchiveValidation {
  if (bytes.length > budget.maxArchiveSizeMb * 1024 * 1024) {
    return { ok: false, entries: [], errors: [`archive upload exceeds the ${budget.maxArchiveSizeMb}MB budget (§9)`], totalUncompressedBytes: 0 };
  }
  const parsed = readZipCentralDirectory(bytes);
  if ("error" in parsed) return { ok: false, entries: [], errors: [parsed.error], totalUncompressedBytes: 0 };
  return validateArchiveEntries(parsed.entries, budget);
}

/**
 * Build a minimal stored (uncompressed) ZIP — fixture/test support so
 * hostile-archive tests run against REAL archive bytes, not mocks of the
 * validator's own input shape.
 */
export function createStoredZip(entries: { name: string; data?: string; unixMode?: number }[]): Uint8Array {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  const central: Uint8Array[] = [];
  let offset = 0;
  const crcTable: number[] = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crcTable[n] = c >>> 0;
  }
  const crc32 = (data: Uint8Array): number => {
    let c = 0xffffffff;
    for (const b of data) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  for (const entry of entries) {
    const name = encoder.encode(entry.name);
    const data = encoder.encode(entry.data ?? "");
    const crc = crc32(data);
    const local = new Uint8Array(30 + name.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true); // UTF-8 names
    lv.setUint16(8, 0, true); // stored
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, name.length, true);
    local.set(name, 30);
    chunks.push(local, data);
    const cd = new Uint8Array(46 + name.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, name.length, true);
    const external = ((entry.unixMode ?? 0o100644) << 16) >>> 0;
    cv.setUint32(38, external, true);
    cv.setUint32(42, offset, true);
    cd.set(name, 46);
    central.push(cd);
    offset += local.length + data.length;
  }
  const centralSize = central.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, entries.length, true);
  ev.setUint16(10, entries.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);
  const all = [...chunks, ...central, eocd];
  const out = new Uint8Array(all.reduce((n, c) => n + c.length, 0));
  let at = 0;
  for (const chunk of all) { out.set(chunk, at); at += chunk.length; }
  return out;
}
