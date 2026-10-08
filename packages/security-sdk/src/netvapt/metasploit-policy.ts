/**
 * Controlled Metasploit verification policy (Prompt 33 §75–§82,
 * §149/§150).
 *
 * No Metasploit adapter or transport exists in this platform (Prompt 16
 * built the controlled-validation model instead). V2 therefore ships
 * the POLICY LAYER the spec requires, with the transport honestly
 * NOT_PROVISIONED: verification requests are evaluated against the
 * allowlist + payload policy + scope, recorded with a full audit
 * trail, and NEVER executed by an automated path.
 *
 * Structural blocks (§79–§81): reverse shells, bind shells, Meterpreter
 * sessions, persistence, credential dumping, lateral movement and
 * privilege escalation are rejected by policy construction — the
 * allowlist contains ONLY non-destructive check-style verification
 * modules, and any payload-bearing request is refused outright.
 * No persistent interactive sessions exist (§80).
 */

export type VerificationTransportState = "NOT_PROVISIONED";

export interface MetasploitVerificationModule {
  moduleId: string;
  title: string;
  /** What the module proves — check-style evidence only. */
  proves: string;
  destructive: false;
  requiresFindingClass: string;
}

/** §78: the reviewed verification-module allowlist. Check-only modules:
 *  version/condition probes that return evidence. Nothing here opens a
 *  session, delivers a payload or touches credentials. */
export const METASPLOIT_VERIFICATION_ALLOWLIST: MetasploitVerificationModule[] = [
  { moduleId: "auxiliary/scanner/smb/smb_version", title: "SMB Version Scan (check)", proves: "SMB dialect/version evidence for a specific host", destructive: false, requiresFindingClass: "ANY" },
  { moduleId: "auxiliary/scanner/http/http_version", title: "HTTP Version Scan (check)", proves: "HTTP server version evidence for a specific host", destructive: false, requiresFindingClass: "ANY" },
  { moduleId: "auxiliary/scanner/ssh/ssh_version", title: "SSH Version Scan (check)", proves: "SSH banner/version evidence for a specific host", destructive: false, requiresFindingClass: "ANY" },
  { moduleId: "auxiliary/scanner/ssl/openssl_heartbleed", title: "OpenSSL Heartbleed CHECK", proves: "Heartbeat-extension condition evidence (check mode only)", destructive: false, requiresFindingClass: "TLS_HEARTBLEED" },
  { moduleId: "auxiliary/scanner/smb/smb_ms17_010", title: "MS17-010 CHECK", proves: "SMBv1 transaction condition evidence (check mode only)", destructive: false, requiresFindingClass: "SMB_MS17_010" },
];

const FORBIDDEN_CAPABILITY_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /reverse.*shell|bind.*shell|meterpreter/i, label: "shell/session payloads" },
  { pattern: /persistence|persist/i, label: "persistence" },
  { pattern: /credential.*dump|mimikatz|hashdump|sekurlsa/i, label: "credential dumping" },
  { pattern: /lateral|psexec|pass.?the.?hash|pivot/i, label: "lateral movement" },
  { pattern: /privilege.*escalat|getsystem|escalat/i, label: "privilege escalation" },
  { pattern: /payload|exploit\//i, label: "exploit/payload modules" },
];

export interface MetasploitVerificationRequestInput {
  moduleId: string;
  /** §77: a SPECIFIC target + a SPECIFIC finding — both mandatory. */
  targetHost: string;
  findingId: string;
  /** Free-text intent — screened for forbidden capabilities (§79). */
  intentDescription?: string;
  payloadRequested?: string;
  /** Caller holds RUN_CONTROLLED_METASPLOIT_VERIFICATION (§130). */
  controlledVerificationPermission: boolean;
  /** §77: explicit authorization covering this exact host. */
  hostAuthorized: boolean;
  /** §150: the host is inside the frozen scope snapshot. */
  hostInScope: boolean;
}

export interface MetasploitVerificationVerdict {
  decision: "APPROVED_FOR_MANUAL_CONTROLLED_RUN" | "REJECTED" | "BLOCKED";
  reasons: string[];
  /** The transport is never provisioned in this build (§75). */
  transport: VerificationTransportState;
  /** Safe checks to prefer instead (§82) — always listed. */
  preferredSafeVerification: string[];
}

const SAFE_ALTERNATIVES = [
  "version/configuration recheck via governed Nmap service detection (§82)",
  "scanner confirmation via a governed vulnerability re-scan (§82)",
  "safe protocol proof via the VULN_APPROVED NSE check set (§82)",
];

export function evaluateMetasploitVerification(input: MetasploitVerificationRequestInput): MetasploitVerificationVerdict {
  const reasons: string[] = [];
  let blocked = false;

  const module = METASPLOIT_VERIFICATION_ALLOWLIST.find((m) => m.moduleId === input.moduleId);
  if (!module) {
    reasons.push(`Module "${input.moduleId}" is not in the reviewed verification allowlist (§78) — only allowlisted check modules can ever be requested`);
    blocked = true;
  }
  const probeText = `${input.intentDescription ?? ""} ${input.payloadRequested ?? ""} ${input.moduleId}`;
  for ( const { pattern, label } of FORBIDDEN_CAPABILITY_PATTERNS) {
    if (pattern.test(probeText)) {
      reasons.push(`Request involves ${label} — structurally forbidden in automated verification (§79/§81)`);
      blocked = true;
    }
  }
  if (input.payloadRequested) {
    reasons.push("Payload delivery is forbidden: verification modules run check-style only, no payloads (§79)");
    blocked = true;
  }
  if (!input.findingId) { reasons.push("A specific finding is required — verification is never a fishing expedition (§77)"); blocked = true; }
  if (!input.targetHost) { reasons.push("A specific target host is required (§77)"); blocked = true; }
  if (!input.hostAuthorized) { reasons.push("No explicit authorization covers this host (§77)"); blocked = true; }
  if (!input.hostInScope) { reasons.push("Target host is outside the frozen scope snapshot — BLOCKED (§150)"); blocked = true; }
  if (!input.controlledVerificationPermission) {
    reasons.push("Caller lacks the separate RUN_CONTROLLED_METASPLOIT_VERIFICATION permission (§130)");
  }
  if (blocked) return { decision: "BLOCKED", reasons, transport: "NOT_PROVISIONED", preferredSafeVerification: SAFE_ALTERNATIVES };
  if (reasons.length > 0) return { decision: "REJECTED", reasons, transport: "NOT_PROVISIONED", preferredSafeVerification: SAFE_ALTERNATIVES };
  return {
    decision: "APPROVED_FOR_MANUAL_CONTROLLED_RUN",
    reasons: ["Request satisfies §77 (explicit authorization, specific target + finding, allowlisted check module, separate permission). The transport is NOT_PROVISIONED in this build: the request is recorded for a human-controlled run and is never executed automatically."],
    transport: "NOT_PROVISIONED",
    preferredSafeVerification: SAFE_ALTERNATIVES,
  };
}
