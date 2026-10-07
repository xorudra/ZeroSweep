/**
 * Prompt 17 — artifact intake (§5/§6/§8).
 *
 * Upload validation is by MAGIC BYTES, never by extension alone;
 * archive structure is validated with the shared Prompt 12 archive
 * discipline (zip-slip, traversal, symlink escape, decompression
 * bombs, nested archives, file-count/size budgets) BEFORE anything is
 * extracted; the build identity is the SHA-256 of the artifact bytes,
 * never the filename. Nothing here — or anywhere in the intake path —
 * executes the uploaded binary (§8).
 */
import { createHash } from "node:crypto";
import { readZipCentralDirectory, validateArchiveEntries, type ArchiveEntry } from "../code/archive";
import type { SourceScanBudget } from "../code/types";
import { DEFAULT_MOBILE_BUDGET, type MobileArtifactFormat, type MobileScanBudget } from "./types";

/** Magic-byte signatures (§6). APK/AAB/IPA/DEX containers: APK, AAB
 *  and IPA are ZIP containers — distinguished by their required
 *  entries, not by a header; DEX has its own magic. */
export function sniffMobileArtifact(bytes: Uint8Array, entryNames: string[] = []): MobileArtifactFormat {
  if (bytes.length >= 8 && bytes[0] === 0x64 && bytes[1] === 0x65 && bytes[2] === 0x78 && bytes[3] === 0x0a) {
    return "DEX"; // "dex\n"
  }
  const isZip = bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b
    && (bytes[2] === 0x03 || bytes[2] === 0x05 || bytes[2] === 0x07);
  if (!isZip) return "UNKNOWN";
  const names = new Set(entryNames);
  if (names.has("AndroidManifest.xml") && [...names].some((n) => n === "classes.dex" || /^classes\d*\.dex$/.test(n))) return "APK";
  if ([...names].some((n) => n.startsWith("base/") || n === "BundleConfig.pb")) return "AAB";
  if ([...names].some((n) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(n))) return "IPA";
  // A ZIP without the distinguishing entries is not acceptable as a
  // mobile artifact — the caller rejects UNKNOWN.
  return "UNKNOWN";
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

export interface MobileArtifactIntake {
  ok: boolean;
  format: MobileArtifactFormat;
  /** SHA-256 of the artifact bytes — the immutable build identity (§5). */
  artifactHash: string;
  sizeBytes: number;
  entryCount: number;
  errors: string[];
  warnings: string[];
}

const EXTENSION_FORMAT: Record<string, MobileArtifactFormat> = {
  ".apk": "APK", ".aab": "AAB", ".ipa": "IPA", ".dex": "DEX",
};

/**
 * Validate one uploaded artifact (§6): size against the mobile
 * budget, magic bytes, extension agreement (a mismatch is refused —
 * content wins over names), and full archive security over the ZIP
 * central directory when entries are not supplied directly. The
 * whole archive is rejected on any archive-security error (§107).
 * NOTHING is extracted or executed here.
 */
export function validateMobileArtifactUpload(input: {
  fileName: string;
  bytes?: Uint8Array;
  /** Pre-read central-directory entries (large uploads stream their
   *  directory without loading the body); validated identically. */
  entries?: ArchiveEntry[];
  declaredSha256?: string;
  budget?: MobileScanBudget;
}): MobileArtifactIntake {
  const budget = input.budget ?? DEFAULT_MOBILE_BUDGET;
  const errors: string[] = [];
  const warnings: string[] = [];
  const bytes = input.bytes;
  const sizeBytes = bytes ? bytes.length : 0;

  if (bytes && sizeBytes > budget.maxArtifactSizeMb * 1024 * 1024) {
    errors.push(`artifact is ${sizeBytes} bytes — exceeds the ${budget.maxArtifactSizeMb}MB artifact budget (§91)`);
  }
  if (!bytes && !input.entries) {
    errors.push("no artifact bytes or archive directory were supplied — nothing to validate");
  }

  // Archive entries: from bytes (central directory read, no
  // extraction) or supplied by the streaming intake path.
  let entries: ArchiveEntry[] = input.entries ?? [];
  if (bytes && !input.entries) {
    const dir = readZipCentralDirectory(bytes);
    if ("entries" in dir) entries = dir.entries;
    else if (sniffMobileArtifact(bytes) !== "DEX") errors.push(`archive directory unreadable: ${dir.error}`);
  }

  const entryNames = entries.map((e) => e.name);
  const format = bytes ? sniffMobileArtifact(bytes, entryNames) : inferFormatFromEntries(entryNames);
  if (format === "UNKNOWN") {
    errors.push("artifact format is not a recognized APK / AAB / IPA / DEX (magic-byte check, §6)");
  }
  const ext = input.fileName.toLowerCase().slice(input.fileName.lastIndexOf("."));
  const extFormat = EXTENSION_FORMAT[ext];
  if (extFormat && format !== "UNKNOWN" && extFormat !== format) {
    errors.push(`file extension claims ${extFormat} but the content is ${format} — refused (validation is by content, §6)`);
  }

  // Archive security (§6/§107) reuses the Prompt 12 discipline with
  // the mobile budget mapped onto it.
  if (entries.length > 0) {
    const sourceBudget: SourceScanBudget = {
      maxRepositorySizeMb: budget.maxArtifactSizeMb,
      maxFiles: budget.maxExtractedFiles,
      // A single entry larger than the whole artifact budget is
      // refused; the extracted TOTAL is capped separately below.
      maxFileSizeMb: budget.maxArtifactSizeMb,
      maxArchiveSizeMb: budget.maxExtractedBytesMb,
      maxHistoryDepth: 0,
      maxScanDurationSeconds: budget.maxDecompilationSeconds,
      maxSastFindings: 0,
      maxSecretFindings: 0,
      maxDependencies: 0,
      maxSbomSizeMb: 0,
    };
    const validation = validateArchiveEntries(entries, sourceBudget);
    for (const e of validation.errors) errors.push(e);
  }

  const artifactHash = bytes ? sha256Hex(bytes) : (input.declaredSha256 ?? "");
  if (bytes && input.declaredSha256 && input.declaredSha256.toLowerCase() !== artifactHash) {
    errors.push("declared SHA-256 does not match the artifact bytes — the build identity would be wrong (§5)");
  }
  if (!/^[a-f0-9]{64}$/.test(artifactHash)) {
    errors.push("artifact hash is not a SHA-256 — build identity cannot be established (§5)");
  }

  return {
    ok: errors.length === 0,
    format,
    artifactHash,
    sizeBytes,
    entryCount: entries.length,
    errors,
    warnings,
  };
}

function inferFormatFromEntries(names: string[]): MobileArtifactFormat {
  const set = new Set(names);
  if (set.has("AndroidManifest.xml")) return "APK";
  if ([...set].some((n) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(n))) return "IPA";
  if ([...set].some((n) => n.startsWith("base/"))) return "AAB";
  return "UNKNOWN";
}
