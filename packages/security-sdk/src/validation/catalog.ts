import type { ValidationFindingView, ValidationRiskClass } from "./types";

/**
 * Governed validator catalog (Prompt 16 §6/§14/§15, §68/§69). This is a
 * closed allowlist: a validation technique that is not in this catalog
 * CANNOT be planned, approved or executed — there is no generic
 * "run a request" or "run a tool" validator, and no validator accepts a
 * user-supplied payload, template, command or script (§79).
 *
 * Every catalog validator is non-destructive by construction: it repeats
 * a safe observation (header, TLS, exposure, posture, deterministic
 * scanner/SAST recheck) and compares it with the original evidence.
 */

export interface ValidatorParameterSpec {
  name: string;
  type: "string" | "number" | "boolean";
  maxLength?: number;
  /** Closed value set when present — anything else is rejected. */
  enum?: readonly string[];
}

export interface ValidatorDescriptor {
  slug: string;
  name: string;
  validationType: string;
  /** The reused governed capability (§69–§76). Recorded for audit; the
   *  validator never shells out with user input. */
  toolSlug?: string;
  riskClass: ValidationRiskClass;
  description: string;
  parameters: ValidatorParameterSpec[];
  supportsFinding: (finding: ValidationFindingView) => boolean;
}

const hasHost = (f: ValidationFindingView) => Boolean(f.host || f.endpoint);
const cls = (f: ValidationFindingView) => `${f.vulnClass ?? ""} ${f.title}`.toUpperCase();

export const VALIDATOR_CATALOG: ValidatorDescriptor[] = [
  {
    slug: "header-recheck",
    name: "Security Header Recheck",
    validationType: "HTTP_HEADER",
    toolSlug: "httpx",
    riskClass: "SAFE",
    description: "Repeats the original HTTP request and confirms whether the missing/weak security header is still absent (§6/§15). One safe GET, no body submission.",
    parameters: [{ name: "headerName", type: "string", maxLength: 64 }],
    supportsFinding: (f) => hasHost(f) && (cls(f).includes("HEADER") || cls(f).includes("CSP") || cls(f).includes("HSTS") || cls(f).includes("CONTENT-SECURITY")),
  },
  {
    slug: "tls-recheck",
    name: "TLS Configuration Recheck",
    validationType: "TLS",
    toolSlug: "testssl",
    riskClass: "SAFE",
    description: "Repeats the governed TLS assessment (testssl.sh/SSLyze, §70) and confirms the weak protocol/cipher finding still reproduces.",
    parameters: [],
    supportsFinding: (f) => hasHost(f) && (cls(f).includes("TLS") || cls(f).includes("SSL") || cls(f).includes("CERTIFICATE")),
  },
  {
    slug: "endpoint-exposure-recheck",
    name: "Endpoint Exposure Recheck",
    validationType: "EXPOSURE",
    toolSlug: "httpx",
    riskClass: "SAFE",
    description: "Confirms an exposed endpoint is still reachable without authentication (§15). Safe GET only; response bodies are never stored beyond a sanitized summary.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.endpoint) && (cls(f).includes("EXPOS") || cls(f).includes("UNAUTHENTICATED") || cls(f).includes("PUBLICLY ACCESSIBLE") || cls(f).includes("DIRECTORY LISTING")),
  },
  {
    slug: "nuclei-recheck",
    name: "Nuclei Detection Recheck",
    validationType: "SCANNER_RECHECK",
    toolSlug: "nuclei",
    riskClass: "SAFE",
    description: "Repeats the administrator-approved Nuclei detection template that produced the finding (§69). No user-supplied templates; SQLi/XSS findings are validated ONLY by this non-destructive scanner-evidence recheck — no data extraction, no script execution in user sessions (§16/§17).",
    parameters: [{ name: "templateId", type: "string", maxLength: 128 }],
    supportsFinding: (f) => hasHost(f) && (f.sources ?? []).some((s) => s.toLowerCase().includes("nuclei")),
  },
  {
    slug: "service-presence-recheck",
    name: "Service Presence Recheck",
    validationType: "SERVICE",
    toolSlug: "nmap",
    riskClass: "SAFE",
    description: "Confirms a service is still reachable and identifies banner/version using governed Nmap safe profiles (§25/§72). No exploitation of network services.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.host && f.port) && (cls(f).includes("SERVICE") || cls(f).includes("CLEARTEXT") || cls(f).includes("PORT") || cls(f).includes("BANNER")),
  },
  {
    slug: "api-safe-recheck",
    name: "API Safe Recheck",
    validationType: "API_RECHECK",
    toolSlug: "schemathesis",
    riskClass: "SAFE",
    description: "Safe replay of a read-only API request plus header/schema checks (§24). Destructive API operations are never automated.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.endpoint) && (cls(f).includes("API") || cls(f).includes("GRAPHQL") || cls(f).includes("JWT")),
  },
  {
    slug: "cloud-config-recheck",
    name: "Cloud Configuration Recheck",
    validationType: "CLOUD_CONFIGURATION",
    toolSlug: "prowler",
    riskClass: "SAFE",
    description: "READ-ONLY confirmation of a cloud configuration finding — public access, IAM policy metadata, encryption, logging, firewall configuration (§26/§73). Never modifies a resource.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.cloudResourceId || f.cloudProvider),
  },
  {
    slug: "kubernetes-posture-recheck",
    name: "Kubernetes Posture Recheck",
    validationType: "KUBERNETES_POSTURE",
    toolSlug: "kubescape",
    riskClass: "SAFE",
    description: "Confirms security-context, RBAC, network-policy, exposure and image findings from cluster posture data (§28/§75). No privilege-escalation attempts.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.clusterRef),
  },
  {
    slug: "source-recheck",
    name: "Source Code Recheck",
    validationType: "SOURCE_RECHECK",
    toolSlug: "semgrep",
    riskClass: "SAFE",
    description: "Deterministic re-run of the original SAST/secret/dependency rule over the same snapshot (§74): repeats the rule, verifies a vulnerable dependency remains present. Target code is never executed.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.repositoryId || f.filePath || f.componentPurl),
  },
  {
    slug: "container-image-recheck",
    name: "Container Image Recheck",
    validationType: "CONTAINER_IMAGE",
    toolSlug: "trivy",
    riskClass: "SAFE",
    description: "Confirms image digest, package/version and CVE presence by static re-analysis (§27/§75). Images are never executed; no container-escape techniques.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.imageDigest),
  },
  {
    slug: "ad-posture-recheck",
    name: "Active Directory Posture Recheck",
    validationType: "AD_POSTURE",
    toolSlug: "pingcastle",
    riskClass: "SAFE",
    description: "Defensive, read-only posture confirmation from BloodHound data, PingCastle, LDAP inventory and approved SMB metadata (§29/§76): group membership, ACL relationships, trusts, delegation and certificate-template configuration.",
    parameters: [],
    supportsFinding: (f) => Boolean(f.directoryDomainId || f.directoryObjectId),
  },
];

export function getValidator(slug: string): ValidatorDescriptor | undefined {
  return VALIDATOR_CATALOG.find((v) => v.slug === slug);
}

export function validatorsForFinding(finding: ValidationFindingView): ValidatorDescriptor[] {
  return VALIDATOR_CATALOG.filter((v) => v.supportsFinding(finding));
}

/**
 * Prohibited automation (§95/§97): techniques that must NEVER be planned
 * or executed by this engine. They are classified PROHIBITED_AUTOMATION
 * at request time AND refused again by the policy engine and the worker
 * (defense in depth). Some exist only as DISABLED offensive-tool
 * registry descriptors (§30/§31) — metadata, never executors.
 */
export const PROHIBITED_TECHNIQUES = [
  "password-spraying",
  "credential-stuffing",
  "credential-dumping",
  "brute-force",
  "account-lockout-testing",
  "kerberoasting",
  "asrep-roasting",
  "ntlm-poisoning",
  "ntlm-relay",
  "dcsync",
  "ticket-forging",
  "pass-the-hash",
  "privilege-escalation",
  "lateral-movement",
  "persistence",
  "database-dumping",
  "data-extraction",
  "remote-command-execution",
  "command-execution",
  "os-command-execution",
  "malware-deployment",
  "destructive-testing",
  "dos",
  "denial-of-service",
  "container-escape",
  "ssrf-metadata-access",
  "cloud-metadata-access",
  "cookie-theft",
  "session-hijacking",
  "exploit-execution",
  "metasploit-execution",
] as const;

const PROHIBITED_SET = new Set<string>(PROHIBITED_TECHNIQUES);

/** Normalize a free-form technique name for classification. */
export function normalizeTechniqueName(name: string): string {
  return name.trim().toLowerCase().replace(/[\s_]+/g, "-");
}

const SQUASHED_PROHIBITED = new Set([...PROHIBITED_SET].map((p) => p.replace(/-/g, "")));

/** Classify any requested technique. Anything in the prohibited set —
 *  or containing a prohibited fragment (e.g. "kerberoasting-v2") — is
 *  PROHIBITED_AUTOMATION. Comparison ignores hyphens/spacing variants
 *  ("AS-REP roasting" == "asrep-roasting"). Catalog validators are SAFE
 *  (their descriptor risk class wins). Unknown techniques are
 *  REVIEW_REQUIRED, never silently SAFE. */
export function classifyTechnique(name: string): ValidationRiskClass {
  const normalized = normalizeTechniqueName(name);
  const validator = getValidator(normalized);
  if (validator) return validator.riskClass;
  const squashed = normalized.replace(/-/g, "");
  if (SQUASHED_PROHIBITED.has(squashed)) return "PROHIBITED_AUTOMATION";
  for (const p of SQUASHED_PROHIBITED) {
    if (squashed.includes(p) || (p.includes(squashed) && squashed.length >= 6)) return "PROHIBITED_AUTOMATION";
  }
  return "REVIEW_REQUIRED";
}

export function isProhibitedTechnique(name: string): boolean {
  return classifyTechnique(name) === "PROHIBITED_AUTOMATION";
}
