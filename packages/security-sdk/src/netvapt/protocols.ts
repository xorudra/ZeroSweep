import type { NormalizedService } from "../findings/finding.types";
import { sanitizeScannerText } from "../network/sanitize";
import type { NetworkConfidenceBand } from "./types";

/**
 * Protocol analysis, TLS normalization and OS fingerprinting
 * (Prompt 33 §40–§54).
 *
 * This module analyzes EVIDENCE THAT ALREADY EXISTS — service/version
 * detection output, governed script output, TLS scanner results. It
 * never connects, never logs in, and never guesses credentials (§45):
 * there is no Hydra/Medusa/spraying/stuffing path anywhere in this
 * package, and "anonymous access" checks consume recorded protocol
 * responses only, additionally gated by profile flags (§47/§48/§49).
 *
 * Confidence is preserved end-to-end (§39/§42): a weak banner yields a
 * LOW-confidence hint, never a confirmed product/version/OS, and never
 * a confirmed CVE (that discipline is enforced again in correlation).
 */

export interface ProtocolObservation {
  host: string;
  port: number;
  protocol: string;
  kind: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  title: string;
  detail: string;
  evidence: string;
  /** true = the observation itself confirms a finding-grade condition;
   *  false = configuration evidence for analyst review (§44). */
  findingGrade: boolean;
  vulnClass?: string;
}

export interface ProtocolAnalysisOptions {
  /** §47: FTP anonymous-access check enabled by the approved profile. */
  ftpAnonymousCheck?: boolean;
  /** §52: DNS zone-transfer check explicitly authorized. */
  dnsZoneTransferCheck?: boolean;
  /** §48/§49: SMB/LDAP anonymous metadata checks explicitly authorized. */
  anonymousMetadataChecks?: boolean;
}

const WEAK_TLS_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"];
const WEAK_SSH_ALGORITHMS = ["arcfour", "blowfish-cbc", "cast128-cbc", "3des-cbc", "diffie-hellman-group1-sha1", "ssh-dss", "hmac-md5", "hmac-sha1-96"];

/** §46: SSH defensive analysis over ssh2-enum-algos style evidence. */
export function analyzeSshEvidence(input: { host: string; port: number; banner?: string; algorithms?: string[]; protocolVersion?: string }): ProtocolObservation[] {
  const out: ProtocolObservation[] = [];
  const weak = (input.algorithms ?? []).filter((a) => WEAK_SSH_ALGORITHMS.some((w) => a.toLowerCase().includes(w)));
  if (weak.length > 0) {
    out.push({
      host: input.host, port: input.port, protocol: "ssh", kind: "SSH_WEAK_ALGORITHMS",
      severity: "LOW", findingGrade: true, vulnClass: "WEAK_SSH_ALGORITHMS",
      title: "SSH Server Offers Weak Algorithms",
      detail: `The SSH server advertises legacy algorithms (${weak.join(", ")}). No login was attempted — the evidence is the server's own algorithm list (§46).`,
      evidence: sanitizeScannerText(`algorithms: ${(input.algorithms ?? []).join(", ")}`, 1024),
    });
  }
  if (input.protocolVersion && /^1\./.test(input.protocolVersion)) {
    out.push({
      host: input.host, port: input.port, protocol: "ssh", kind: "SSH_PROTOCOL_V1",
      severity: "MEDIUM", findingGrade: true, vulnClass: "SSH_PROTOCOL_VERSION_1",
      title: "SSH Protocol Version 1 Advertised",
      detail: "SSHv1 is cryptographically obsolete. Evidence is the protocol banner only (§46).",
      evidence: sanitizeScannerText(`banner: ${input.banner ?? input.protocolVersion}`, 512),
    });
  }
  return out;
}

/** §43–§52: per-service protocol configuration analysis. */
export function analyzeProtocolServices(
  services: NormalizedService[],
  scriptEvidence: Array<{ host: string; port: number; scriptId: string; output: string }> = [],
  opts: ProtocolAnalysisOptions = {},
): ProtocolObservation[] {
  const out: ProtocolObservation[] = [];
  const scriptFor = (host: string, port: number, id: string) =>
    scriptEvidence.find((e) => e.host === host && e.port === port && e.scriptId === id);

  for (const svc of services) {
    if (svc.state && svc.state !== "OPEN") continue;
    const name = (svc.name ?? "").toLowerCase();
    const host = svc.host; const port = svc.port;

    // FTP (§47): anonymous access is a CHECK over recorded evidence,
    // enabled only by the approved profile; nothing is uploaded or
    // modified — the platform never performs the login itself.
    if ((name === "ftp" || port === 21) && opts.ftpAnonymousCheck) {
      const ev = scriptFor(host, port, "ftp-anon");
      if (ev && /anonymous.*(allowed|ok|access)/i.test(ev.output)) {
        out.push({
          host, port, protocol: "ftp", kind: "FTP_ANONYMOUS_ACCESS",
          severity: "MEDIUM", findingGrade: true, vulnClass: "FTP_ANONYMOUS_ACCESS",
          title: "FTP Anonymous Access Allowed",
          detail: "The governed check recorded an anonymous-access acceptance from the server. The platform does not log in, list, upload or modify files (§47) — the recorded protocol response is the evidence.",
          evidence: sanitizeScannerText(ev.output, 512),
        });
      }
    }

    // SMB (§48): signing + protocol-version posture from governed
    // script evidence (the finding-grade signing rule itself stays in
    // Prompt 10 network-checks; here we add SMBv1 exposure).
    if (name.includes("smb") || name === "microsoft-ds" || name === "netbios-ssn" || port === 445 || port === 139) {
      const ev = scriptFor(host, port, "smb-os-discovery") ?? scriptFor(host, port, "smb2-security-mode");
      if (ev && /\bSMBv1\b|dialects?:.*\bNT LM 0\.12\b/i.test(ev.output)) {
        out.push({
          host, port, protocol: "smb", kind: "SMB_V1_ENABLED",
          severity: "MEDIUM", findingGrade: true, vulnClass: "SMB_V1_ENABLED",
          title: "SMBv1 Protocol Enabled",
          detail: "SMBv1 is obsolete and carries a long history of critical vulnerabilities. Evidence is the server's negotiated dialect list (§48); no credentials were used.",
          evidence: sanitizeScannerText(ev.output, 512),
        });
      }
      if (opts.anonymousMetadataChecks) {
        const guest = scriptFor(host, port, "smb-enum-shares-anon");
        if (guest) {
          out.push({
            host, port, protocol: "smb", kind: "SMB_ANONYMOUS_METADATA",
            severity: "INFORMATIONAL", findingGrade: false,
            title: "SMB Anonymous Metadata Observation",
            detail: "Anonymous-access metadata recorded under explicit authorization (§48). No credential attack of any kind was performed.",
            evidence: sanitizeScannerText(guest.output, 512),
          });
        }
      }
    }

    // DNS (§52): zone transfer only when explicitly authorized; the
    // observation records the server's response to the governed check.
    if ((name === "domain" || name === "dns" || port === 53) && opts.dnsZoneTransferCheck) {
      const ev = scriptFor(host, port, "dns-zone-transfer");
      if (ev && /(transfer|axfr).*(success|complete|records)/i.test(ev.output)) {
        out.push({
          host, port, protocol: "dns", kind: "DNS_ZONE_TRANSFER_ALLOWED",
          severity: "MEDIUM", findingGrade: true, vulnClass: "DNS_ZONE_TRANSFER_ALLOWED",
          title: "DNS Zone Transfer Allowed",
          detail: "An explicitly authorized, bounded zone-transfer check succeeded (§52). Zone contents are evidence for the assessment only and never become scan scope (§21).",
          evidence: sanitizeScannerText(ev.output, 512),
        });
      }
    }

    // LDAP (§49): TLS + anonymous-bind metadata observations only.
    if (name.includes("ldap") || port === 389 || port === 636) {
      if (port === 389 && !svc.tls) {
        out.push({
          host, port, protocol: "ldap", kind: "LDAP_CLEARTEXT",
          severity: "LOW", findingGrade: false,
          title: "LDAP Service Without TLS (389)",
          detail: "Directory traffic on 389 without StartTLS evidence can expose credentials and directory data. Recorded as a configuration observation (§49) — no bind or harvesting was performed.",
          evidence: `service ${name || "ldap"} on ${host}:${port} without TLS indicator`,
        });
      }
    }

    // RDP (§50): NLA/TLS configuration evidence from governed scripts.
    if (name === "ms-wbt-server" || port === 3389) {
      const ev = scriptFor(host, port, "rdp-ntlm-info");
      if (ev && /Security layer:.*(0|SSL)/i.test(ev.output) && !/NLA|CredSSP/i.test(ev.output)) {
        out.push({
          host, port, protocol: "rdp", kind: "RDP_NLA_NOT_REQUIRED",
          severity: "LOW", findingGrade: false,
          title: "RDP Network Level Authentication Not Evident",
          detail: "Governed evidence did not show NLA/CredSSP enforcement (§50). Recorded as configuration evidence — no connection authentication was attempted.",
          evidence: sanitizeScannerText(ev.output, 512),
        });
      }
    }

    // SMTP (§43): STARTTLS posture from banner evidence.
    if ((name === "smtp" || port === 25 || port === 587) && !svc.tls) {
      out.push({
        host, port, protocol: "smtp", kind: "SMTP_STARTTLS_UNKNOWN",
        severity: "INFORMATIONAL", findingGrade: false,
        title: "SMTP Service Observed (TLS posture from banner evidence only)",
        detail: "Mail service recorded for inventory; encryption posture is assessed from TLS-stage evidence where present (§43).",
        evidence: `service ${name || "smtp"} on ${host}:${port}`,
      });
    }
  }
  return out;
}

/* ------------------------------- TLS (§53/§54) ------------------------------- */

export interface TlsServiceEvidence {
  host: string;
  port: number;
  protocolVersions?: string[];
  weakCiphers?: string[];
  certificate?: {
    expired?: boolean;
    hostnameMismatch?: boolean;
    chainIssues?: string[];
    notAfter?: string;
    subject?: string;
  };
  source: string; // testssl | sslyze | nmap-ssl
}

/** §54: normalize TLS evidence into finding-grade observations. */
export function analyzeTlsEvidence(items: TlsServiceEvidence[]): ProtocolObservation[] {
  const out: ProtocolObservation[] = [];
  for (const item of items) {
    const push = (kind: string, severity: ProtocolObservation["severity"], vulnClass: string, title: string, detail: string, evidence: string) =>
      out.push({ host: item.host, port: item.port, protocol: "tls", kind, severity, title, detail, evidence, findingGrade: true, vulnClass });
    for (const proto of item.protocolVersions ?? []) {
      if (WEAK_TLS_PROTOCOLS.includes(proto)) {
        push("TLS_WEAK_PROTOCOL", "MEDIUM", "WEAK_TLS_PROTOCOL", `Weak TLS Protocol Enabled (${proto})`,
          `${proto} is enabled on ${item.host}:${item.port} per ${item.source} evidence (§54).`, `protocols: ${(item.protocolVersions ?? []).join(", ")}`);
      }
    }
    if ((item.weakCiphers ?? []).length > 0) {
      push("TLS_WEAK_CIPHER", "LOW", "WEAK_TLS_CIPHER", "Weak TLS Cipher Suites Offered",
        `Weak cipher suites reported by ${item.source}: ${(item.weakCiphers ?? []).join(", ")} (§54).`, `weak ciphers: ${(item.weakCiphers ?? []).join(", ")}`);
    }
    const cert = item.certificate;
    if (cert?.expired) {
      push("TLS_CERT_EXPIRED", "MEDIUM", "EXPIRED_CERTIFICATE", "Expired TLS Certificate",
        `The certificate presented by ${item.host}:${item.port} is expired${cert.notAfter ? ` (notAfter ${cert.notAfter})` : ""} (§54).`, `subject: ${cert.subject ?? "unknown"}, source: ${item.source}`);
    }
    if (cert?.hostnameMismatch) {
      push("TLS_HOSTNAME_MISMATCH", "MEDIUM", "CERTIFICATE_HOSTNAME_MISMATCH", "TLS Certificate Hostname Mismatch",
        `The certificate presented by ${item.host}:${item.port} does not match the hostname (§54).`, `subject: ${cert.subject ?? "unknown"}, source: ${item.source}`);
    }
    for (const issue of cert?.chainIssues ?? []) {
      push("TLS_CHAIN_ISSUE", "LOW", "CERTIFICATE_CHAIN_ISSUE", "TLS Certificate Chain Issue",
        `${issue} (§54, source ${item.source}).`, sanitizeScannerText(issue, 256));
    }
  }
  return out;
}

/* ------------------------------- OS fingerprinting (§40–§42) ------------------------------- */

export interface OsFingerprint {
  host: string;
  family: string;
  versionHint?: string;
  confidence: number; // 0..1
  band: NetworkConfidenceBand;
  source: string;
  observedAt: string;
}

export function networkConfidenceBand(confidence: number): NetworkConfidenceBand {
  if (confidence >= 0.95) return "VERIFIED";
  if (confidence >= 0.75) return "HIGH";
  if (confidence >= 0.45) return "MEDIUM";
  return "LOW";
}

/**
 * §40–§42: OS observations preserve uncertainty. A fingerprint becomes
 * an observation with its confidence attached — a weak match stays a
 * LOW hint and is never promoted to a confirmed OS anywhere downstream.
 */
export function makeOsFingerprint(input: { host: string; family: string; versionHint?: string; confidence: number; source: string; observedAt?: string }): OsFingerprint {
  const confidence = Math.max(0, Math.min(1, input.confidence));
  return {
    host: input.host, family: input.family,
    ...(input.versionHint && confidence >= 0.45 ? { versionHint: input.versionHint } : {}),
    confidence, band: networkConfidenceBand(confidence),
    source: input.source, observedAt: input.observedAt ?? new Date().toISOString(),
  };
}
