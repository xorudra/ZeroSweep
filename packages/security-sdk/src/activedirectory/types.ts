/**
 * Prompt 15 — Active Directory Security Engine: shared domain types
 * and governed policies (§2–§120).
 *
 * The engine is DEFENSIVE: inventory, configuration review, identity
 * relationships, privilege analysis, exposure analysis and attack-PATH
 * MODELING over collected data. The spec's DO-NOT list (§120) is
 * implemented as ABSENCE: no password spraying, credential brute
 * force, hash dumping, credential theft, NTLM relay, poisoning,
 * Kerberoasting, AS-REP roasting, pass-the-hash/ticket, DCSync,
 * DCShadow, remote execution, lateral movement, persistence,
 * privilege escalation or AD CS exploitation exists anywhere in this
 * module — offensive tools are registered as DISABLED descriptors
 * (§47/§51–§55) so policy can name them, exactly like Pacu in P14.
 */
import type {
  NormalizedCertificateAuthority, NormalizedCertificateTemplate, NormalizedDirectoryComputer,
  NormalizedDirectoryData, NormalizedDirectoryDomainInfo, NormalizedDirectoryGpo,
  NormalizedDirectoryGroup, NormalizedDirectoryOU, NormalizedDirectoryRelationship,
  NormalizedDirectorySnapshot, NormalizedDirectoryTrust, NormalizedDirectoryUser,
  NormalizedDomainController, NormalizedSmbShare,
} from "../findings/finding.types";

export type {
  NormalizedCertificateAuthority, NormalizedCertificateTemplate, NormalizedDirectoryComputer,
  NormalizedDirectoryData, NormalizedDirectoryDomainInfo, NormalizedDirectoryGpo,
  NormalizedDirectoryGroup, NormalizedDirectoryOU, NormalizedDirectoryRelationship,
  NormalizedDirectorySnapshot, NormalizedDirectoryTrust, NormalizedDirectoryUser,
  NormalizedDomainController, NormalizedSmbShare,
};

export const AD_PROFILES = [
  "AD_INVENTORY", "AD_BASELINE", "AD_COMPREHENSIVE", "ADCS_POSTURE",
  "SMB_POSTURE", "IDENTITY_GRAPH", "ATTACK_PATH_ANALYSIS",
] as const;
export type AdProfile = (typeof AD_PROFILES)[number];

export const AD_TARGET_TYPES = [
  "ACTIVE_DIRECTORY", "ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST",
  "DOMAIN_CONTROLLER", "LDAP_DIRECTORY",
] as const;

/** A registered AD domain as the store resolves it (§4): identity +
 *  credential-profile REFERENCE only. There is deliberately no field
 *  that could hold a password, a hash or a ticket (§7/§19). */
export interface DirectoryDomainRecord {
  id: string;
  dnsName: string;
  netbiosName?: string;
  domainSid?: string;
  functionalLevel?: string;
  forestId?: string;
  environment?: string;
  criticality?: string;
  credentialProfileId?: string;
  credentialReference?: string;
  identityKind?: string; // READ_ONLY_DOMAIN | APPROVED_DIRECTORY_AUDITOR
  dcHosts: string[];
}

/** The read-only directory assessment policy (§7/§8/§83). READ_ONLY is
 *  the only mode: the platform NEVER modifies a user, group, GPO, ACL,
 *  template or account, and never requires Domain Admin. */
export interface DirectoryAssessmentPolicy {
  mode: "READ_ONLY";
  allowDirectoryModification: false;
  allowCredentialAttacks: false;
  allowExploitation: false;
  allowLateralMovement: false;
  requireDomainAdmin: false;
}

export const DIRECTORY_ASSESSMENT_POLICY: DirectoryAssessmentPolicy = {
  mode: "READ_ONLY",
  allowDirectoryModification: false,
  allowCredentialAttacks: false,
  allowExploitation: false,
  allowLateralMovement: false,
  requireDomainAdmin: false,
};

/** Least-privilege guidance (§7/§8): the assessment identity needs
 *  directory READ access only; authenticated users can typically read
 *  the posture metadata this engine analyzes. */
export const DIRECTORY_READ_ONLY_GUIDANCE = {
  preferredIdentity: "A dedicated read-only domain account (READ_ONLY_DOMAIN) or an approved directory auditor identity (APPROVED_DIRECTORY_AUDITOR) — never Domain Admin for normal scans (§8)",
  permissions: ["Directory read (authenticated user default)", "Read GPO metadata", "Read AD CS configuration (pKIEnrollmentService / templates)"],
} as const;

/** An ephemeral directory credential lease record (§9): reference NAME
 *  + lifecycle only, TTL-capped like cloud leases. Credential material
 *  never appears in this record, Redis payloads, logs, API responses,
 *  frontend state, audit metadata or finding evidence (§9/§113). */
export interface DirectoryLeaseRecord {
  directoryDomainId: string;
  credentialReference: string;
  scanId?: string;
  purpose: string;
  status: "ISSUED" | "CONSUMED" | "EXPIRED" | "RELEASED";
  issuedAt: string;
  expiresAt: string;
}

export const MAX_DIRECTORY_LEASE_SECONDS = 3600;

export function issueDirectoryLease(input: {
  directoryDomainId: string; credentialReference: string; scanId?: string;
  purpose?: string; ttlSeconds?: number; now?: Date;
}): DirectoryLeaseRecord {
  const now = input.now ?? new Date();
  const ttl = Math.min(Math.max(input.ttlSeconds ?? 900, 60), MAX_DIRECTORY_LEASE_SECONDS);
  return {
    directoryDomainId: input.directoryDomainId,
    credentialReference: input.credentialReference,
    ...(input.scanId ? { scanId: input.scanId } : {}),
    purpose: input.purpose ?? "DIRECTORY_ASSESSMENT",
    status: "ISSUED",
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + ttl * 1000).toISOString(),
  };
}

// ── Privileged group classification (§22) ────────────────────────────

/** Well-known privileged-group RIDs (the SID suffix). Classification
 *  keys off the SID, never the localized display name (§22): group
 *  names are administrator-controlled text and differ per locale. */
export const PRIVILEGED_GROUP_RIDS: Record<string, { name: string; class: "PRIVILEGED" | "HIGH_IMPACT" }> = {
  "512": { name: "Domain Admins", class: "PRIVILEGED" },
  "518": { name: "Schema Admins", class: "PRIVILEGED" },
  "519": { name: "Enterprise Admins", class: "PRIVILEGED" },
  "544": { name: "Administrators", class: "PRIVILEGED" },
  "548": { name: "Account Operators", class: "HIGH_IMPACT" },
  "549": { name: "Server Operators", class: "HIGH_IMPACT" },
  "550": { name: "Print Operators", class: "HIGH_IMPACT" },
  "551": { name: "Backup Operators", class: "HIGH_IMPACT" },
  "520": { name: "Group Policy Creator Owners", class: "HIGH_IMPACT" },
};

/** Domain-relative RID of a SID: the final numeric component. Returns
 *  undefined for well-known SIDs (S-1-5-32-*) — those use the full
 *  suffix after the last dash as well, which the same rule yields. */
export function sidRid(sid: string | undefined): string | undefined {
  if (!sid) return undefined;
  const m = /-(\d+)$/.exec(sid.trim());
  return m ? m[1] : undefined;
}

export function classifyGroupPrivilege(input: { objectId?: string; name?: string }): "PRIVILEGED" | "HIGH_IMPACT" | "STANDARD" {
  const rid = sidRid(input.objectId);
  if (rid && PRIVILEGED_GROUP_RIDS[rid]) return PRIVILEGED_GROUP_RIDS[rid]!.class;
  // Builtin groups live under S-1-5-32-<rid> (e.g. Administrators -544);
  // sidRid already returns that final component, so the map covers it.
  return "STANDARD";
}

export function isPrivilegedGroup(input: { objectId?: string; name?: string }): boolean {
  return classifyGroupPrivilege(input) !== "STANDARD";
}

// ── SharpHound collection policy (§29) ───────────────────────────────

export const SHARPHOUND_COLLECTION_METHODS = [
  "MEMBERSHIP", "ACL", "TRUSTS", "CONTAINER", "OBJECT_PROPERTIES",
  "LOCAL_GROUPS", "SESSIONS", "LOGGED_ON", "RDP", "DCOM", "PS_REMOTE",
] as const;
export type SharpHoundCollectionMethod = (typeof SHARPHOUND_COLLECTION_METHODS)[number];

export type CollectionClassification = "SAFE" | "REVIEW_REQUIRED" | "DISABLED";

/** §29: inventory/relationship collection is SAFE; session and
 *  local-access collection is REVIEW_REQUIRED (session data is
 *  sensitive, §69 — collected only under explicit policy); anything
 *  unrecognized is DISABLED (default-deny). Credential/session-content
 *  theft is not a SharpHound collection method at all — it is absent
 *  here by design (§120). */
export const SHARPHOUND_METHOD_CLASSIFICATION: Record<string, CollectionClassification> = {
  MEMBERSHIP: "SAFE",
  ACL: "SAFE",
  TRUSTS: "SAFE",
  CONTAINER: "SAFE",
  OBJECT_PROPERTIES: "SAFE",
  LOCAL_GROUPS: "REVIEW_REQUIRED",
  SESSIONS: "REVIEW_REQUIRED",
  LOGGED_ON: "REVIEW_REQUIRED",
  RDP: "REVIEW_REQUIRED",
  DCOM: "REVIEW_REQUIRED",
  PS_REMOTE: "REVIEW_REQUIRED",
};

/** Default automated collection (§29): SAFE methods only. */
export const SHARPHOUND_DEFAULT_METHODS: SharpHoundCollectionMethod[] = [
  "MEMBERSHIP", "ACL", "TRUSTS", "CONTAINER", "OBJECT_PROPERTIES",
];

export interface CollectionPolicyVerdict {
  allowed: boolean;
  approved: string[];
  denied: { method: string; classification: CollectionClassification; reason: string }[];
}

export function evaluateSharpHoundCollectionPolicy(requested: string[], opts: { allowReviewRequired?: boolean } = {}): CollectionPolicyVerdict {
  const approved: string[] = [];
  const denied: CollectionPolicyVerdict["denied"] = [];
  for (const raw of requested) {
    const method = raw.toUpperCase();
    const classification = SHARPHOUND_METHOD_CLASSIFICATION[method] ?? "DISABLED";
    if (classification === "SAFE") approved.push(method);
    else if (classification === "REVIEW_REQUIRED" && opts.allowReviewRequired) approved.push(method);
    else denied.push({
      method, classification,
      reason: classification === "REVIEW_REQUIRED"
        ? `collection method ${method} is REVIEW_REQUIRED (§29/§69): automated collection uses SAFE methods only unless an administrator approves the review-required set`
        : `collection method ${method} is DISABLED (§29): not a governed collection method`,
    });
  }
  return { allowed: denied.length === 0, approved, denied };
}

// ── Stale account policy (§63) ───────────────────────────────────────

export interface StaleAccountPolicy {
  /** Days since last logon (or password set, when logon is unknown)
   *  after which an ENABLED account is reported stale. Organization-
   *  configurable — there is no universal number (§63). */
  staleDays: number;
  /** Privileged stale accounts are escalated one severity band. */
  escalatePrivileged: boolean;
}

export const DEFAULT_STALE_ACCOUNT_POLICY: StaleAccountPolicy = { staleDays: 90, escalatePrivileged: true };

export function clampStaleAccountPolicy(input: Partial<StaleAccountPolicy> = {}): StaleAccountPolicy {
  const days = typeof input.staleDays === "number" && Number.isFinite(input.staleDays)
    ? Math.min(Math.max(Math.floor(input.staleDays), 7), 3650)
    : DEFAULT_STALE_ACCOUNT_POLICY.staleDays;
  return { staleDays: days, escalatePrivileged: input.escalatePrivileged ?? DEFAULT_STALE_ACCOUNT_POLICY.escalatePrivileged };
}

// ── Scan budget (§87) + rate limits (§88) ───────────────────────────

export interface DirectoryBudget {
  maxDomains: number;
  maxDirectoryObjects: number;
  maxUsers: number;
  maxGroups: number;
  maxComputers: number;
  maxRelationships: number;
  maxLdapQueries: number;
  maxSmbHosts: number;
  maxAttackPaths: number;
  maxGraphDepth: number;
  maxArtifactSize: number;
  maxScanDuration: number;
}

export const DEFAULT_DIRECTORY_BUDGET: DirectoryBudget = {
  maxDomains: 5, maxDirectoryObjects: 50000, maxUsers: 25000, maxGroups: 5000,
  maxComputers: 10000, maxRelationships: 100000, maxLdapQueries: 2000,
  maxSmbHosts: 256, maxAttackPaths: 500, maxGraphDepth: 8,
  maxArtifactSize: 64 * 1024 * 1024, maxScanDuration: 3600,
};

export const DIRECTORY_BUDGET_CAPS: DirectoryBudget = {
  maxDomains: 50, maxDirectoryObjects: 500000, maxUsers: 250000, maxGroups: 50000,
  maxComputers: 100000, maxRelationships: 1000000, maxLdapQueries: 20000,
  maxSmbHosts: 4096, maxAttackPaths: 5000, maxGraphDepth: 16,
  maxArtifactSize: 512 * 1024 * 1024, maxScanDuration: 14400,
};

export function clampDirectoryBudget(input: Partial<DirectoryBudget> = {}): DirectoryBudget {
  const out = { ...DEFAULT_DIRECTORY_BUDGET };
  for (const key of Object.keys(out) as (keyof DirectoryBudget)[]) {
    const v = input[key];
    if (typeof v === "number" && Number.isFinite(v) && v > 0) {
      out[key] = Math.min(Math.floor(v), DIRECTORY_BUDGET_CAPS[key]);
    }
  }
  return out;
}

/** Bounded concurrency discipline (§88): directory work must never
 *  overload domain controllers. */
export const DIRECTORY_THROTTLE = {
  ldapMaxConcurrency: 2, smbMaxConcurrency: 4, dnsMaxConcurrency: 4, graphMaxConcurrency: 1,
  ldapPageSize: 1000, // §17: paged enumeration, never one giant response
} as const;

// ── AD CS risk classes (§50) ─────────────────────────────────────────

/** Governed ESC-style condition classes. These are ANALYSIS LABELS
 *  over template/CA configuration metadata — the platform stores the
 *  condition, the affected template/CA, evidence, risk explanation
 *  and remediation (§50). It never exploits them (§48/§120). */
export const ADCS_RISK_CLASSES: Record<string, { title: string; severity: "CRITICAL" | "HIGH" | "MEDIUM"; explanation: string; remediation: string }> = {
  ESC1: {
    title: "Template allows enrollee-supplied subject with client-authentication EKU and no approval",
    severity: "CRITICAL",
    explanation: "A template that lets a low-privileged enrollee supply an arbitrary subject AND is usable for client authentication, without manager approval or authorized signatures, is a known risky configuration class (ESC1-style). Analysis label only — no certificate is requested.",
    remediation: "Disable enrollee-supplied subject (use AD-built subject), require manager approval, and restrict enrollment permissions to the intended group.",
  },
  ESC2: {
    title: "Template with broad issuance purpose (any-purpose / no EKU) enrollable by low-privileged principals",
    severity: "HIGH",
    explanation: "Templates with any-purpose or absent EKUs can be repurposed beyond their intended use when enrollment is broadly granted (ESC2-style). Analysis label only.",
    remediation: "Constrain EKUs to the intended purpose and restrict enrollment permissions.",
  },
  ESC3: {
    title: "Enrollment-agent template without application policy restrictions",
    severity: "HIGH",
    explanation: "An enrollment-agent template (Certificate Request Agent EKU) without application-policy restrictions lets agents enroll on behalf of others broadly (ESC3-style). Analysis label only.",
    remediation: "Apply application policy restrictions and authorized-signature requirements to enrollment-agent templates.",
  },
  ESC4: {
    title: "Template ACL grants dangerous write control to a non-privileged principal",
    severity: "CRITICAL",
    explanation: "A principal outside the privileged set holding GENERIC_ALL / WRITE_OWNER / WRITE_DACL over a template can rewrite its configuration into an exploitable state (ESC4-style). Analysis label only — ACLs are never modified by the platform.",
    remediation: "Remove the dangerous write rights; template ACLs should be writable only by CA administrators.",
  },
  ESC6: {
    title: "CA policy allows requesters to specify SAN (EDITF_ATTRIBUTESUBJECTALTNAME2 observed)",
    severity: "HIGH",
    explanation: "A CA whose edit flags allow the requester to specify a subjectAltName can issue certificates for arbitrary identities to anyone who can enroll (ESC6-style). Analysis label only.",
    remediation: "Clear the EDITF_ATTRIBUTESUBJECTALTNAME2 policy flag on the CA.",
  },
  ESC8: {
    title: "Web enrollment endpoint exposed without EPA / channel-binding requirement",
    severity: "MEDIUM",
    explanation: "An enrollment web endpoint observed without Extended Protection for Authentication metadata is a relay-risk configuration class (ESC8-style). The platform records configuration only — no relay is ever attempted (§120).",
    remediation: "Require EPA/channel binding on enrollment endpoints or disable web enrollment where unused.",
  },
};

// ── Offensive tool registrations (§47/§51–§56/§103) ──────────────────

/** A governed registration for a tool the platform will NOT execute
 *  automatically. Mirrors the Pacu pattern (P14 §34): visible in the
 *  Tools surface with its capability split and DISABLED default, with
 *  NO adapter behind it — policy can name it, stages never select it. */
export interface OffensiveToolRegistration {
  slug: string;
  name: string;
  classification: string;
  riskLevel: "INTRUSIVE" | "RESTRICTED" | "MODERATE" | "LOW";
  status: "DISABLED";
  enabled: false;
  requiresApproval: true;
  /** Capabilities that exist ONLY as policy names (never implemented). */
  disabledCapabilities: string[];
  /** The defensive slice that IS permitted, for tools that have one. */
  permittedCapabilities: string[];
  note: string;
}

export const NETEXEC_REGISTRATION: OffensiveToolRegistration = {
  slug: "netexec",
  name: "NetExec",
  classification: "OFFENSIVE_REMOTE_OPERATIONS",
  riskLevel: "INTRUSIVE",
  status: "DISABLED", enabled: false, requiresApproval: true,
  disabledCapabilities: ["OFFENSIVE_REMOTE_OPERATIONS", "CREDENTIAL_ATTACKS"],
  permittedCapabilities: ["SAFE_SERVICE_ENUMERATION", "AUTHENTICATED_INVENTORY"],
  note: "§51: only a safe, approved inventory capability may ever be enabled for NetExec; OFFENSIVE_REMOTE_OPERATIONS and CREDENTIAL_ATTACKS are DISABLED. No adapter is implemented in this phase — service enumeration is covered by the network engine and SMB inventory by SMBMap.",
};

export const IMPACKET_REGISTRATION: OffensiveToolRegistration = {
  slug: "impacket",
  name: "Impacket",
  classification: "OFFENSIVE_MODULES_DISABLED",
  riskLevel: "INTRUSIVE",
  status: "DISABLED", enabled: false, requiresApproval: true,
  disabledCapabilities: ["OFFENSIVE_REMOTE_OPERATIONS", "CREDENTIAL_ATTACKS", "OFFENSIVE_AD_OPERATIONS"],
  permittedCapabilities: [],
  note: "§52: Impacket is registered as a tool family with sensitive modules classified separately. OFFENSIVE_MODULES_DISABLED by default — remote execution, credential dumping, Kerberos abuse, NTLM relay, DCSync and ticket manipulation are never implemented (§120).",
};

export const KERBRUTE_REGISTRATION: OffensiveToolRegistration = {
  slug: "kerbrute",
  name: "Kerbrute",
  classification: "ACCOUNT_AUTHENTICATION_TESTING",
  riskLevel: "INTRUSIVE",
  status: "DISABLED", enabled: false, requiresApproval: true,
  disabledCapabilities: ["ACCOUNT_AUTHENTICATION_TESTING"],
  permittedCapabilities: [],
  note: "§53: Kerbrute performs account/authentication testing — DISABLED. No automated username enumeration or password spraying exists in standard AD scans (§61/§120). Password/authentication auditing is a separate, tightly controlled phase.",
};

export const RESPONDER_REGISTRATION: OffensiveToolRegistration = {
  slug: "responder",
  name: "Responder",
  classification: "NETWORK_POISONING",
  riskLevel: "RESTRICTED",
  status: "DISABLED", enabled: false, requiresApproval: true,
  disabledCapabilities: ["NETWORK_POISONING", "CREDENTIAL_CAPTURE"],
  permittedCapabilities: [],
  note: "§54: Responder is a network poisoner / credential capture tool (HIGH/INTRUSIVE) — DISABLED, never run automatically (§120).",
};

export const POWERVIEW_REGISTRATION: OffensiveToolRegistration = {
  slug: "powerview",
  name: "PowerView",
  classification: "OFFENSIVE_AD_OPERATIONS",
  riskLevel: "INTRUSIVE",
  status: "DISABLED", enabled: false, requiresApproval: true,
  disabledCapabilities: ["OFFENSIVE_AD_OPERATIONS"],
  permittedCapabilities: ["DIRECTORY_ENUMERATION"],
  note: "§55: PowerView automatic offensive execution is DISABLED. Standard inventory uses LDAP/SharpHound/native directory APIs instead.",
};

export const ADEXPLORER_REGISTRATION: OffensiveToolRegistration = {
  slug: "adexplorer",
  name: "ADExplorer",
  classification: "MANUAL_DIRECTORY_ANALYSIS",
  riskLevel: "LOW",
  status: "DISABLED", enabled: false, requiresApproval: true,
  disabledCapabilities: [],
  permittedCapabilities: ["MANUAL_DIRECTORY_ANALYSIS", "SNAPSHOT_IMPORT"],
  note: "§56: ADExplorer is supported as MANUAL_DIRECTORY_ANALYSIS / SNAPSHOT_IMPORT — its snapshots can be imported like BloodHound exports; interactive GUI behavior is never automated.",
};

/** All DISABLED offensive/manual registrations (§102/§103). */
export const AD_DISABLED_REGISTRATIONS: OffensiveToolRegistration[] = [
  NETEXEC_REGISTRATION, IMPACKET_REGISTRATION, KERBRUTE_REGISTRATION,
  RESPONDER_REGISTRATION, POWERVIEW_REGISTRATION, ADEXPLORER_REGISTRATION,
];

/** Certipy's capability split (§47): posture capabilities are the only
 *  ones an adapter implements; ADCS_OFFENSIVE_VALIDATION is DISABLED /
 *  APPROVAL_REQUIRED and has no implementation. */
export const CERTIPY_CAPABILITY_SPLIT = {
  implemented: ["ADCS_INVENTORY", "ADCS_POSTURE_ANALYSIS"],
  disabled: ["ADCS_OFFENSIVE_VALIDATION"],
} as const;

/** Attack-path statuses (§35). COMPROMISED is deliberately absent from
 *  the type: a path may never be labelled COMPROMISED without actual
 *  incident evidence, which a configuration assessment never has. */
export const ATTACK_PATH_STATUSES = ["THEORETICAL", "EVIDENCE_BACKED", "REVIEWED", "MITIGATED"] as const;
export type AttackPathStatus = (typeof ATTACK_PATH_STATUSES)[number];
