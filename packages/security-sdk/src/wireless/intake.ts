/**
 * Prompt 19 — wireless capture intake (§26–§30/§83–§85).
 *
 * Uploaded captures are UNTRUSTED INPUT (§28): format is proven from
 * MAGIC BYTES, never the file extension (§27); size is bounded by
 * the wireless budget before any parsing (§61/§85); identity is the
 * SHA-256 (§26). Parsing itself runs later, in the isolated worker
 * sandbox (§28) — this module only validates and describes.
 * Raw captures are protected artifacts: metadata travels in rows,
 * bytes live in object storage, and raw access is permission-gated
 * (VIEW_RAW_WIRELESS_CAPTURES) and audited (§30/§96).
 */
import { createHash } from "node:crypto";
import { DEFAULT_WIRELESS_BUDGET, type WirelessScanBudget } from "./types";

export type WirelessCaptureFormat = "PCAP" | "PCAPNG" | "UNKNOWN";

/** §27: magic-byte format proof — pcap (both endiannesses + the
 *  nanosecond variant) and pcapng section-header block type. */
export function detectCaptureFormat(prefix: Buffer | Uint8Array): WirelessCaptureFormat {
  if (prefix.length >= 4) {
    const b = Buffer.from(prefix.subarray(0, 4));
    const hex = b.toString("hex");
    if (hex === "a1b2c3d4" || hex === "d4c3b2a1" || hex === "a1b23c4d" || hex === "4d3cb2a1") return "PCAP";
    if (hex === "0a0d0d0a") return "PCAPNG";
  }
  return "UNKNOWN";
}

export interface WirelessCaptureUpload {
  name: string;
  sizeBytes: number;
  declaredSha256?: string;
  magicPrefix?: Buffer | Uint8Array;
  /** Content bytes where the caller already holds them (tests/API
   *  bounded uploads) — used for hash + magic when provided. */
  content?: Buffer;
}

export interface WirelessCaptureIntakeResult {
  accepted: boolean;
  reason?: string;
  reasonCode?: string;
  format?: WirelessCaptureFormat;
  sha256?: string;
}

export function validateWirelessCaptureUpload(
  upload: WirelessCaptureUpload,
  budget: WirelessScanBudget = DEFAULT_WIRELESS_BUDGET,
): WirelessCaptureIntakeResult {
  if (!upload.name || upload.name.trim().length === 0) {
    return { accepted: false, reasonCode: "CAPTURE_NAME_REQUIRED", reason: "a capture name is required" };
  }
  if (!Number.isFinite(upload.sizeBytes) || upload.sizeBytes <= 0) {
    return { accepted: false, reasonCode: "CAPTURE_EMPTY", reason: "capture is empty" };
  }
  // §61/§85: oversized captures are refused BEFORE parsing.
  if (upload.sizeBytes > budget.maxCaptureBytes || upload.sizeBytes > budget.maxArtifactSizeBytes) {
    return {
      accepted: false, reasonCode: "CAPTURE_EXCEEDS_BUDGET",
      reason: `capture of ${upload.sizeBytes} bytes exceeds the wireless budget (maxCaptureBytes ${budget.maxCaptureBytes}) — refused before parsing (§61/§85)`,
    };
  }
  const prefix = upload.content ? upload.content.subarray(0, 4) : upload.magicPrefix;
  const format = prefix ? detectCaptureFormat(prefix) : "UNKNOWN";
  if (!prefix || format === "UNKNOWN") {
    return {
      accepted: false, reasonCode: "CAPTURE_FORMAT_UNPROVEN",
      reason: "capture format could not be proven from magic bytes — extension is never trusted (§27)",
    };
  }
  let sha256: string | undefined;
  if (upload.content) sha256 = createHash("sha256").update(upload.content).digest("hex");
  if (upload.declaredSha256 && sha256 && upload.declaredSha256.toLowerCase() !== sha256) {
    return { accepted: false, reasonCode: "CAPTURE_HASH_MISMATCH", reason: "declared SHA-256 does not match the capture content (§26)" };
  }
  return { accepted: true, format, ...(sha256 ?? upload.declaredSha256 ? { sha256: (sha256 ?? upload.declaredSha256 ?? "").toLowerCase() } : {}) };
}

/** §84: a truncated/malformed capture must fail SAFELY — header
 *  sanity check the worker runs before handing bytes to tshark. */
export function captureHeaderSanity(bytes: Buffer): { ok: boolean; reason?: string } {
  const format = detectCaptureFormat(bytes);
  if (format === "UNKNOWN") return { ok: false, reason: "unrecognized capture magic — parser refuses the artifact (§84)" };
  if (format === "PCAP" && bytes.length < 24) return { ok: false, reason: "truncated pcap global header (§84)" };
  if (format === "PCAPNG" && bytes.length < 28) return { ok: false, reason: "truncated pcapng section header (§84)" };
  return { ok: true };
}
