import { redactScannerSecrets } from "./vuln-scanners";

/**
 * Packet-capture governance + analysis (Prompt 33 §83–§93,
 * §151/§152).
 *
 * Captures are PASSIVE (§85/§93): the platform records and summarizes
 * traffic on an authorized interface; it never injects, modifies or
 * replays traffic — no such function exists in this module. Every
 * capture is permissioned, duration/size bounded (§84/§87), stored as
 * restricted evidence (§88), and viewed under the separate
 * VIEW_PACKET_CAPTURE permission (§89). Summaries redact credentials,
 * tokens and payload content before they exist (§90).
 */

export const PACKET_CAPTURE_LIMITS = {
  /** §84/§87: absolute capture bounds — requests above are rejected. */
  maxDurationSeconds: 3_600,
  maxSizeBytes: 2_147_483_648, // 2 GiB
  maxFilterLength: 512,
} as const;

export interface PacketCaptureRequest {
  interfaceReference: string;
  /** The interface must be an AUTHORIZED interface (§84) — an opaque
   *  reference to worker configuration, never a raw device path. */
  interfaceAuthorized: boolean;
  durationSeconds: number;
  sizeLimitBytes: number;
  /** BPF-style filter text — validated as data, bounded (§84). */
  filter?: string;
  callerCanCreate: boolean; // CREATE_PACKET_CAPTURE
  storageQuotaBytes: number;
  storageUsedBytes: number;
}

export interface PacketCaptureVerdict {
  allowed: boolean;
  reasons: string[];
  /** Effective bounded values when allowed (§87). */
  effective?: { durationSeconds: number; sizeLimitBytes: number };
}

export function evaluatePacketCapture(request: PacketCaptureRequest): PacketCaptureVerdict {
  const reasons: string[] = [];
  if (!request.callerCanCreate) reasons.push("Caller lacks CREATE_PACKET_CAPTURE (§129)");
  if (!request.interfaceAuthorized) reasons.push("Capture interface is not an authorized interface reference (§84)");
  if (request.durationSeconds <= 0) reasons.push("Capture duration must be positive (§84)");
  if (request.durationSeconds > PACKET_CAPTURE_LIMITS.maxDurationSeconds) {
    reasons.push(`Capture duration ${request.durationSeconds}s exceeds the platform maximum of ${PACKET_CAPTURE_LIMITS.maxDurationSeconds}s — rejected, not clamped (§151)`);
  }
  if (request.sizeLimitBytes <= 0) reasons.push("Capture size limit must be positive (§87)");
  if (request.sizeLimitBytes > PACKET_CAPTURE_LIMITS.maxSizeBytes) {
    reasons.push(`Capture size limit exceeds the platform maximum of ${PACKET_CAPTURE_LIMITS.maxSizeBytes} bytes — rejected (§151)`);
  }
  if (request.filter && request.filter.length > PACKET_CAPTURE_LIMITS.maxFilterLength) reasons.push("Capture filter exceeds the maximum length (§84)");
  if (request.filter && /[;|&$`\\]/.test(request.filter)) reasons.push("Capture filter contains shell metacharacters — treated as hostile data (§137)");
  if (request.storageUsedBytes + request.sizeLimitBytes > request.storageQuotaBytes) {
    reasons.push("Capture would exceed the workspace packet-evidence storage quota (§87)");
  }
  if (reasons.length > 0) return { allowed: false, reasons };
  return { allowed: true, reasons: [], effective: { durationSeconds: request.durationSeconds, sizeLimitBytes: request.sizeLimitBytes } };
}

/* --------------------------- Analysis (§91/§92) --------------------------- */

export interface TsharkProtocolRecord {
  frameProtocol: string;
  sourceIp?: string;
  destIp?: string;
  sourcePort?: number;
  destPort?: number;
  /** Protocol metadata fields only — payloads never enter analysis. */
  info?: string;
  tlsVersion?: string;
  dnsQuery?: string;
  dnsResponseCode?: string;
}

export interface PacketSummary {
  packetCount: number;
  protocolCounts: Record<string, number>;
  /** §90: summary text is redacted before it exists. */
  notes: string[];
}

export interface PacketFinding {
  kind: "PLAINTEXT_PROTOCOL" | "WEAK_PROTOCOL" | "UNEXPECTED_SERVICE" | "TLS_METADATA" | "DNS_ANOMALY";
  severity: "MEDIUM" | "LOW" | "INFORMATIONAL";
  title: string;
  detail: string;
}

const PLAINTEXT_PROTOCOLS = new Set(["telnet", "ftp", "http", "pop3", "imap", "smtp", "snmp"]);
const WEAK_PROTOCOL_MARKERS = ["sslv2", "sslv3", "tlsv1.0", "tlsv1.1", "ssl"];

/**
 * §91/§92: structured protocol metadata → security observations,
 * inside the authorized capture context only. Unexpected-service
 * detection compares observed flows against the authorized service
 * inventory supplied by the caller (§92).
 */
export function analyzePacketMetadata(
  records: TsharkProtocolRecord[],
  opts: { expectedServices?: Array<{ port: number; protocol: string }>; knownSecrets?: string[] } = {},
): { summary: PacketSummary; findings: PacketFinding[] } {
  const protocolCounts: Record<string, number> = {};
  const findings: PacketFinding[] = [];
  const seen = new Set<string>();
  const expected = new Set((opts.expectedServices ?? []).map((s) => `${s.port}/${s.protocol.toLowerCase()}`));

  const add = (f: PacketFinding, key: string) => { if (!seen.has(key)) { seen.add(key); findings.push(f); } };

  for (const rec of records) {
    const proto = rec.frameProtocol.toLowerCase();
    protocolCounts[proto] = (protocolCounts[proto] ?? 0) + 1;
    if (PLAINTEXT_PROTOCOLS.has(proto)) {
      add({ kind: "PLAINTEXT_PROTOCOL", severity: "MEDIUM", title: `Cleartext protocol observed in capture (${proto})`, detail: `${proto} traffic was observed inside the authorized capture. Summaries never include payload content (§90).` }, `plain:${proto}`);
    }
    const versionText = (rec.tlsVersion ?? rec.info ?? "").toLowerCase();
    if (rec.tlsVersion || proto.includes("tls") || proto.includes("ssl")) {
      if (WEAK_PROTOCOL_MARKERS.some((m) => versionText.includes(m))) {
        add({ kind: "WEAK_PROTOCOL", severity: "MEDIUM", title: "Weak TLS version observed in capture", detail: `A flow negotiated a legacy TLS/SSL version (${rec.tlsVersion ?? "per metadata"}) inside the authorized capture (§92).` }, `weak:${rec.tlsVersion}`);
      } else {
        add({ kind: "TLS_METADATA", severity: "INFORMATIONAL", title: "TLS metadata observed", detail: "TLS flows present; version/SNI metadata recorded without payload content (§90/§92)." }, "tlsmeta");
      }
    }
    if (proto === "dns" && rec.dnsResponseCode && rec.dnsResponseCode.toUpperCase() === "NXDOMAIN") {
      add({ kind: "DNS_ANOMALY", severity: "LOW", title: "DNS NXDOMAIN responses observed", detail: "Repeated failed DNS resolutions can indicate misconfiguration or malware lookups — recorded as an observation for analyst review, not a finding against a host (§92)." }, "dns:nxdomain");
    }
    if (expected.size > 0 && typeof rec.destPort === "number") {
      const key = `${rec.destPort}/${proto}`;
      if (!expected.has(key) && !PLAINTEXT_PROTOCOLS.has(proto)) {
        add({ kind: "UNEXPECTED_SERVICE", severity: "LOW", title: `Unexpected service flow observed (${key})`, detail: `Traffic to ${key} is not in the authorized service inventory for this capture context (§92).` }, `unexpected:${key}`);
      }
    }
  }

  const notes = [
    `${records.length} frames summarized across ${Object.keys(protocolCounts).length} protocols`,
    "Payloads, credentials and session tokens are excluded from summaries by construction (§90)",
  ].map((n) => redactScannerSecrets(n, opts.knownSecrets ?? []));

  return { summary: { packetCount: records.length, protocolCounts, notes }, findings };
}
