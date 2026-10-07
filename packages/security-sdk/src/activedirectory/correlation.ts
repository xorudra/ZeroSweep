/**
 * Prompt 15 — directory correlation (§61/§71–§72).
 *
 * One canonical issue = one canonical finding, whichever tool saw it
 * first: the fingerprint is derived from the DOMAIN + the canonical
 * RULE + the affected directory OBJECT, so a native analyzer, a
 * PingCastle rule mapped to the same canonical rule (§109), a
 * SharpHound-derived observation and a re-scan all converge. DC
 * vulnerability correlation (§72) chains DomainController → network
 * Asset (hostname/IP match) → services → network findings → CVE → KEV
 * → AD criticality; the matcher here is the deterministic identity
 * half of that chain — it links identities, never severity.
 */
import { createHash } from "node:crypto";
import type { NormalizedDomainController } from "./types";

/** Rules that can only occur ONCE per domain (the KRBTGT account is a
 *  domain singleton): their fingerprint is domain + rule, so a native
 *  observation (which knows the object id) and a PingCastle rule
 *  (which does not) converge on ONE canonical finding (§109). */
export const DIRECTORY_SINGLETON_RULES = new Set(["AD_KRBTGT_OLD"]);

/** Canonical directory finding fingerprint: sha256 over the stable
 *  structured key (domain + rule + object). Never derived from free
 *  text, never from a tool's own id — tools converge, §61. */
export function directoryFingerprint(input: {
  domainRef: string;
  ruleId: string;
  objectId?: string;
  objectType?: string;
}): string {
  const singleton = DIRECTORY_SINGLETON_RULES.has(input.ruleId);
  const key = ["ad", input.domainRef.toLowerCase(), input.ruleId, singleton ? "" : (input.objectType ?? ""), singleton ? "" : (input.objectId ?? "")].join("|");
  return createHash("sha256").update(key).digest("hex");
}

/** Canonicalize a tool-specific rule id: PingCastle models and
 *  scanner-specific ids that the governed map (§109) recognizes fold
 *  onto the native rule id; everything else keeps its identity. */
const CANONICAL_RULE_ALIASES: Record<string, string> = {
  "pingcastle:privileged-accounts-count": "AD_PRIVILEGED_GROUP_EXCESS",
  "pingcastle:krbtgt": "AD_KRBTGT_OLD",
  "pingcastle:smbv1": "AD_SMB1_ENABLED",
};

export function canonicalDirectoryRuleId(ruleId: string): string {
  return CANONICAL_RULE_ALIASES[ruleId.toLowerCase()] ?? ruleId;
}

export interface DirectoryAssetCandidate {
  assetId: string;
  hostname?: string;
  ipAddresses: string[];
}

/** Match a domain controller to the network Asset P10 discovered for
 *  the same host (§6/§72): exact hostname/FQDN match (case-insensitive)
 *  wins; otherwise a shared IP address. Returns undefined when there is
 *  no deterministic match — the DC is then its own inventory row, never
 *  duplicated as a host and never force-linked. */
export function matchDomainControllerAsset(
  dc: Pick<NormalizedDomainController, "hostname" | "dnsName" | "ipAddresses">,
  candidates: DirectoryAssetCandidate[],
): string | undefined {
  const names = new Set([dc.hostname.toLowerCase(), (dc.dnsName ?? "").toLowerCase()].filter(Boolean));
  for (const c of candidates) {
    if (c.hostname && names.has(c.hostname.toLowerCase())) return c.assetId;
  }
  const ips = new Set(dc.ipAddresses);
  for (const c of candidates) {
    if (c.ipAddresses.some((ip) => ips.has(ip))) return c.assetId;
  }
  return undefined;
}

/** Deterministic remediation guidance (§82): recommendations only —
 *  the platform never changes AD itself (no user deletion, no
 *  membership/GPO/ACL/template modification, no account disablement). */
export const DIRECTORY_REMEDIATION: Record<string, string> = {
  AD_PRIVILEGED_GROUP_EXCESS: "Review every member; move daily-use accounts out of privileged groups and use dedicated, vaulted admin accounts with tiered administration.",
  AD_NESTED_PRIVILEGED_GROUP: "Flatten or document the nested path; privileged membership through nesting is still privileged access — remove indirect grants that are not intentional.",
  AD_DANGEROUS_ACL: "Remove the excessive right from the principal; directory ACLs on high-value objects should grant write-class rights only to the owning admin tier. (Performed by directory administrators — the platform never modifies ACLs.)",
  AD_UNCONSTRAINED_DELEGATION: "Replace unconstrained delegation with constrained or resource-based constrained delegation scoped to the specific services required.",
  AD_CONSTRAINED_DELEGATION_REVIEW: "Confirm each delegation target is still required and scoped to the minimum services; prefer resource-based constrained delegation.",
  AD_PREAUTH_NOT_REQUIRED: "Re-enable Kerberos pre-authentication for the account unless a documented legacy dependency exists; investigate why it was disabled.",
  AD_SPN_SERVICE_ACCOUNT: "Confirm the service account is required, vault its credential in the secret manager, rotate it, and prefer a group Managed Service Account (gMSA). Presence of an SPN alone is not a vulnerability — this finding fires only with the recorded risk factors.",
  AD_PASSWORD_NEVER_EXPIRES: "Remove the never-expires flag for interactive accounts and enforce the domain password policy; service accounts should use gMSA or vaulted rotation.",
  AD_PASSWORD_NOT_REQUIRED: "Clear the password-not-required flag and set a compliant password; accounts that may authenticate without a password are a critical hygiene failure.",
  AD_STALE_ENABLED_ACCOUNT: "Review with the account owner; disable or remove accounts that are no longer needed. (Performed by directory administrators — the platform never disables accounts.)",
  AD_DISABLED_PRIVILEGED_ACCOUNT: "Remove privileged membership from disabled accounts or delete the accounts after the retention review.",
  AD_PASSWORD_POLICY_WEAK: "Strengthen the domain password policy (length ≥ 14, lockout threshold and duration) or apply a fine-grained policy to privileged users.",
  AD_LDAP_SIGNING_NOT_REQUIRED: "Require LDAP signing on domain controllers (policy: Domain controller: LDAP server signing requirements = Require signing) after client compatibility testing.",
  AD_LDAP_CHANNEL_BINDING_WEAK: "Set LDAP channel binding to Always (EPA) on domain controllers after client compatibility testing.",
  AD_SMB1_ENABLED: "Disable SMBv1 on the host and confirm no legacy dependency remains.",
  AD_SMB_SIGNING_NOT_REQUIRED: "Require SMB signing on servers and domain controllers after compatibility testing.",
  AD_SMB_ANONYMOUS_SHARE: "Remove anonymous access from the share; grant named groups the minimum required permission.",
  AD_SMB_WRITABLE_SHARE: "Reduce the share permission to the minimum required; broadly writable shares are staging points for tampering.",
  AD_TRUST_REVIEW: "Review the trust's business need; enable SID filtering and selective authentication where compatible, and document the accepted risk otherwise.",
  AD_DC_SERVICE_EXPOSURE: "Restrict the exposed DC service to the networks that require it; domain controller services should not be reachable from untrusted segments.",
  AD_KRBTGT_OLD: "Rotate the KRBTGT password twice (with replication convergence between rotations) per Microsoft guidance.",
  ADCS_TEMPLATE_RISK: "Restrict enrollment permissions, require manager approval, and remove enrollee-supplied subject / any-purpose EKUs as the class guidance specifies. (Performed by PKI administrators — the platform never modifies templates.)",
  ADCS_CA_CONFIGURATION: "Correct the CA policy flag per the class guidance and audit issued certificates from the exposure window.",
};

export function directoryRemediation(ruleId: string): string | undefined {
  return DIRECTORY_REMEDIATION[ruleId];
}
