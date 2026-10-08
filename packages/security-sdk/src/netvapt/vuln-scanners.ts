import type { NormalizedVulnFinding } from "../vuln/types";
import type { ParsedScannerReport } from "../vulnmgmt/scanners";
import { sanitizeScannerText } from "../network/sanitize";
import type { NetworkConfidenceBand } from "./types";
import { networkConfidenceBand } from "./protocols";

/**
 * Vulnerability-scanner integration for Network VAPT V2
 * (Prompt 33 §55–§68, §143–§145, §155).
 *
 * The scanners themselves are the Prompt 11 connectors (Greenbone /
 * Nessus) with Prompt 11 parsers — V2 adds the network layer on top:
 * profile mapping (§57), CanonicalFindingCandidate normalization with
 * plugin provenance (§64–§66), credential security (§59–§63) and the
 * scanner-outcome discipline (§155): an unavailable scanner makes the
 * scan PARTIAL/ERROR — it NEVER reads as "no vulnerabilities".
 *
 * Credential rule (§62): scanner API credentials and credentialed-scan
 * credentials are secret REFERENCES end to end. Any secret VALUE that
 * appears in scanner output, evidence or a report is redacted before
 * normalization — the §143 test plants a synthetic secret and proves
 * its absence from every normalized field.
 */

export interface NetworkFindingCandidate {
  assetHost: string;
  ip?: string;
  hostname?: string;
  port?: number;
  transport: string;
  service?: string;
  protocol?: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  confidence: number;
  confidenceBand: NetworkConfidenceBand;
  cve?: string;
  cwe?: string;
  cvssScore?: number;
  /** Plugin provenance (§66) — always recorded, never stripped. */
  plugin: { scanner: string; pluginId: string; pluginName: string; feedContext?: string };
  evidence: string;
  remediation?: string;
  references: string[];
  observedAt: string;
  /** Correlation fingerprint (§69): host+port+transport+vuln identity. */
  fingerprint: string;
  /** CPE the scanner itself reported, when present (§68). */
  cpe?: string;
  /** Evidence strength for the product/version attribution (§68). */
  versionEvidence: "SCANNER_CONFIRMED" | "BANNER_ONLY" | "NONE";
}

/** Secret-value patterns redacted from ALL normalized output (§62/§143).
 *  Values are replaced, never partially masked — a partial secret is
 *  still a secret. */
const SECRET_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\b(?:api[-_ ]?key|access[-_ ]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}/gi, label: "[REDACTED-SECRET]" },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/g, label: "[REDACTED-SECRET]" },
  { pattern: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, label: "Bearer [REDACTED-SECRET]" },
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, label: "[REDACTED-PRIVATE-KEY]" },
];

export function redactScannerSecrets(text: string, knownSecrets: string[] = []): string {
  let out = text;
  for (const secret of knownSecrets) {
    if (secret && secret.length >= 4) out = out.split(secret).join("[REDACTED-SECRET]");
  }
  for (const { pattern, label } of SECRET_PATTERNS) out = out.replace(pattern, label);
  return out;
}

/** §57/§58 (Prompt 11 logical profiles): V2 profile → scanner profile.
 *  Only administrator-mapped logical profiles exist — arbitrary unsafe
 *  scanner settings are never exposed through this mapping. */
export function scannerLogicalProfile(product: "GREENBONE" | "NESSUS", v2ProfileKey: string): string | undefined {
  if (v2ProfileKey === "NETWORK_VULNERABILITY") return product === "GREENBONE" ? "STANDARD" : "NETWORK_STANDARD";
  if (v2ProfileKey === "NETWORK_STANDARD") return product === "GREENBONE" ? "BASELINE" : "NETWORK_BASELINE";
  return undefined;
}

export interface NormalizeScannerOptions {
  /** Secret VALUES known to the run (scanner API keys, credentialed-scan
   *  credentials) — redacted from every output field (§62/§143). */
  knownSecrets?: string[];
  observedAt?: string;
}

export function networkFindingFingerprint(input: { host: string; port?: number; transport: string; cve?: string; vulnClass: string; title: string }): string {
  const identity = input.cve ?? input.vulnClass ?? input.title.toLowerCase().replace(/[^a-z0-9]+/g, "-").slice(0, 64);
  return `net:${input.host.toLowerCase()}:${input.port ?? 0}/${input.transport.toLowerCase()}:${identity}`;
}

/** §64–§66: normalize a parsed scanner report into network candidates. */
export function normalizeScannerReport(report: ParsedScannerReport, opts: NormalizeScannerOptions = {}): NetworkFindingCandidate[] {
  const secrets = opts.knownSecrets ?? [];
  const clean = (value: string | undefined, cap: number): string => sanitizeScannerText(redactScannerSecrets(value ?? "", secrets), cap);
  return report.findings.map((f: NormalizedVulnFinding) => {
    const pluginId = f.evidenceDetail?.checkId ?? f.signatureFamily ?? "unknown";
    const cpe = typeof f.evidenceDetail?.metadata?.cpe === "string" ? f.evidenceDetail.metadata.cpe : undefined;
    const versionEvidence: NetworkFindingCandidate["versionEvidence"] = cpe ? "SCANNER_CONFIRMED" : f.sourceConfidence >= 0.75 ? "SCANNER_CONFIRMED" : "BANNER_ONLY";
    return {
      assetHost: f.host ?? "unknown",
      ...(f.host && /^\d{1,3}(\.\d{1,3}){3}$/.test(f.host) ? { ip: f.host } : f.host ? { hostname: f.host } : {}),
      ...(typeof f.port === "number" ? { port: f.port } : {}),
      transport: (f.protocol ?? "tcp").toLowerCase(),
      ...(typeof f.evidenceDetail?.metadata?.service === "string" ? { service: f.evidenceDetail.metadata.service } : {}),
      ...(f.protocol ? { protocol: f.protocol } : {}),
      title: clean(f.title, 500),
      description: clean(f.description, 4000),
      severity: f.severity,
      confidence: f.sourceConfidence,
      confidenceBand: networkConfidenceBand(f.sourceConfidence),
      ...(f.cve ? { cve: f.cve } : {}),
      ...(f.cwe ? { cwe: f.cwe } : {}),
      ...(typeof f.cvssScore === "number" ? { cvssScore: f.cvssScore } : {}),
      plugin: {
        scanner: f.sourceTool, pluginId: clean(pluginId, 128), pluginName: clean(f.title, 300),
        ...(report.scannerVersion ? { feedContext: `${report.scanner} ${report.scannerVersion}` } : {}),
      },
      evidence: clean(f.evidence, 4000),
      ...(f.remediation ? { remediation: clean(f.remediation, 2000) } : {}),
      references: f.references ?? [],
      observedAt: opts.observedAt ?? new Date().toISOString(),
      fingerprint: networkFindingFingerprint({ host: f.host ?? "unknown", ...(typeof f.port === "number" ? { port: f.port } : {}), transport: (f.protocol ?? "tcp").toLowerCase(), ...(f.cve ? { cve: f.cve } : {}), vulnClass: f.vulnClass, title: f.title }),
      ...(cpe ? { cpe } : {}),
      versionEvidence,
    };
  });
}

/* ------------------------- Scanner outcome (§155) ------------------------- */

export type VulnScanOutcome =
  | { kind: "COMPLETED"; findings: number }
  | { kind: "PARTIAL"; findings: number; gaps: string[] }
  | { kind: "ERROR"; gaps: string[] };

/**
 * §155: scanner failure is NEVER a clean result. If any planned
 * vulnerability scanner was unavailable/errored, the outcome is PARTIAL
 * (some results) or ERROR (none), with the gap named — the phrase
 * "no vulnerabilities" cannot be produced by this function.
 */
export function deriveVulnScanOutcome(input: {
  plannedScanners: string[];
  completedScanners: string[];
  failedScanners: Array<{ slug: string; reason: string }>;
  findings: number;
}): VulnScanOutcome {
  const gaps = input.failedScanners.map((f) => `${f.slug} unavailable: ${f.reason} — its coverage is MISSING, not clean (§155)`);
  const missingPlanned = input.plannedScanners.filter((s) => !input.completedScanners.includes(s) && !input.failedScanners.some((f) => f.slug === s));
  for (const slug of missingPlanned) gaps.push(`${slug} did not complete — its coverage is MISSING, not clean (§155)`);
  if (gaps.length === 0) return { kind: "COMPLETED", findings: input.findings };
  if (input.completedScanners.length === 0) return { kind: "ERROR", gaps };
  return { kind: "PARTIAL", findings: input.findings, gaps };
}

/* --------------------- Credentialed scanning (§60–§63) --------------------- */

export interface CredentialedScanRequest {
  /** Secret REFERENCE only — a value here is a contract violation. */
  credentialReference: string;
  /** The ONE scanner allowed to receive the credential (§61). */
  targetScanner: string;
  /** Scanners that must never see it (§61). */
  otherScanners: string[];
  /** Credential validation attempts permitted — lockout-safe (§63). */
  validationAttempts?: number;
}

export interface CredentialedScanVerdict {
  allowed: boolean;
  reasons: string[];
  /** The injection plan: exactly one recipient (§61). */
  injectionPlan?: { recipient: string; excluded: string[]; validationAttempts: number; temporary: true };
}

/**
 * §60–§63: credentialed scanning foundation. Credentials are explicitly
 * provided, scoped to ONE scanner, referenced (never valued), temporary,
 * and validated with a single bounded attempt — no lockout behavior,
 * no retry storms, and an auth failure is recorded as a coverage gap
 * (§145), never retried aggressively.
 */
export function evaluateCredentialedScan(request: CredentialedScanRequest, opts: { credentialedPermission: boolean; credentialExists: boolean }): CredentialedScanVerdict {
  const reasons: string[] = [];
  if (!opts.credentialedPermission) reasons.push("Caller lacks RUN_CREDENTIALLED_NETWORK_SCAN (§129)");
  if (!opts.credentialExists) reasons.push("Credential reference does not resolve to a stored secret reference (§60)");
  if (!request.credentialReference || /^(password|secret|token)$/i.test(request.credentialReference)) {
    reasons.push("credentialReference must be a secret-store reference, never a value (§59/§62)");
  }
  if (request.otherScanners.includes(request.targetScanner)) reasons.push("Target scanner also appears in the exclusion list — ambiguous injection plan (§61)");
  const attempts = request.validationAttempts ?? 1;
  if (attempts > 1) reasons.push(`Credential validation is limited to a single attempt to avoid account lockout (§63) — requested ${attempts}`);
  if (reasons.length > 0) return { allowed: false, reasons };
  return {
    allowed: true, reasons: [],
    injectionPlan: { recipient: request.targetScanner, excluded: request.otherScanners, validationAttempts: 1, temporary: true },
  };
}

/** §145: an auth failure becomes a coverage limitation, verbatim. */
export function authFailureLimitation(scanner: string, host: string): string {
  return `Credentialed scan authentication failed on ${host} (${scanner}) — recorded as a coverage gap; no retry or brute-force follows (§145)`;
}
