/**
 * Prompt 15 — shared bases for Active Directory adapters
 * (§7/§13/§14/§41/§44/§48/§113/§120).
 *
 * Built on the recon lifecycle like the cloud families. The directory
 * disciplines every adapter inherits:
 *  - configuration carries a registered domain id + a credential
 *    REFERENCE name only; credential-looking keys AND caller-supplied
 *    LDAP filter/base/query keys are REJECTED at validation (§14:
 *    typed, platform-generated queries only — no arbitrary LDAP or
 *    shell construction can be expressed through config);
 *  - parser context (domain id/ref) is assembled from worker-derived
 *    config only, never client input;
 *  - network policy is CUSTOM_ALLOWLIST: the only egress is the
 *    assessed domain's approved DCs / in-scope hosts (§11).
 */
import { ReconAdapterBase, type ReconPlanParts } from "../recon/recon-adapter.base";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsed, type ReconParser } from "../recon/parsers-common";
import type { NormalizedDirectoryData } from "./types";
import { isValidCredentialReference } from "./guards";

export function dirConfigStr(config: Record<string, unknown>, key: string): string | undefined {
  const v = config[key];
  return typeof v === "string" && v.length > 0 ? v : undefined;
}

export function dirConfigStrList(config: Record<string, unknown>, key: string): string[] {
  const v = config[key];
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}

/** §7/§14/§113 config discipline for ALL directory adapters. */
export function assertDirectoryConfig(config: Record<string, unknown>): void {
  for (const key of Object.keys(config)) {
    if (/credential|secret|token|password|privatekey|hash|ticket/i.test(key) && key !== "credentialReference") {
      throw new AdapterConfigurationError(`directory config key "${key}" is forbidden: credentials exist only as secret references (§7/§113)`);
    }
    if (/^(filter|searchfilter|searchbase|base|query|ldapquery|command|args|shell|exec)$/i.test(key)) {
      throw new AdapterConfigurationError(`directory config key "${key}" is forbidden: queries are typed and platform-generated — arbitrary LDAP/shell construction is not expressible (§14)`);
    }
  }
  const ref = config.credentialReference;
  if (ref !== undefined && (typeof ref !== "string" || !isValidCredentialReference(ref))) {
    throw new AdapterConfigurationError("credentialReference must be a secret-manager reference NAME — credential values never travel in scan configuration (§7/§113)");
  }
}

export interface DirectoryParserContext {
  toolSlug: string;
  domainId?: string;
  domainRef: string; // DNS name of the assessed domain
}

/** The parsed payload every Prompt 15 adapter produces: findings plus
 *  the normalized directory payload. */
export interface ParsedDirectory {
  findings: import("../findings/finding.types").NormalizedFinding[];
  directory?: NormalizedDirectoryData;
  metrics: Record<string, number>;
}

export function emptyParsedDirectory(metrics: Record<string, number> = {}): ParsedDirectory {
  return { findings: [], metrics };
}

export abstract class DirectoryAdapterBase extends ReconAdapterBase {
  protected abstract parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory;
  protected abstract directoryPlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts;

  protected readonly parser: ReconParser = { tool: "activedirectory", parse: () => emptyParsed() };

  protected lastConfig: Record<string, unknown> = {};

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    // The directory discipline runs FIRST so a forbidden key reports
    // as the §7/§14 violation it is, not a generic unknown-key error.
    assertDirectoryConfig(config);
    await super.validateConfiguration(config);
    this.lastConfig = config;
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return this.directoryPlan(target, config);
  }

  protected override planNetworkPolicy(): "CUSTOM_ALLOWLIST" {
    return "CUSTOM_ALLOWLIST";
  }

  protected parserContext(): DirectoryParserContext {
    const c = this.lastConfig;
    return {
      toolSlug: this.metadata.slug,
      ...(dirConfigStr(c, "directoryDomainId") ? { domainId: dirConfigStr(c, "directoryDomainId")! } : {}),
      domainRef: dirConfigStr(c, "directoryDomainRef") ?? "unknown-domain",
    };
  }

  override async parse(raw: string): Promise<ParsedDirectory> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    return text ? this.parseDirectory(text, this.parserContext()) : emptyParsedDirectory();
  }

  override async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedDirectory;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      ...(p.directory ? { directory: p.directory } : {}),
      artifacts: [],
      metrics: { ...(p.metrics ?? {}) },
      mock: false,
    };
  }
}

/** Governed LDAP query kinds (§14): the ONLY ldapsearch queries the
 *  platform can build. Each maps to a platform-generated filter over
 *  platform-chosen attributes — a caller picks the KIND, never text. */
export const LDAP_QUERY_KINDS = [
  "DOMAIN_INFO", "USERS", "GROUPS", "COMPUTERS", "TRUSTS", "PASSWORD_POLICY", "GPO_METADATA",
] as const;
export type LdapQueryKind = (typeof LDAP_QUERY_KINDS)[number];

export const LDAP_QUERY_TEMPLATES: Record<LdapQueryKind, { baseSuffix: string; filter: string; attributes: string[] }> = {
  DOMAIN_INFO: {
    baseSuffix: "",
    filter: "(objectClass=domain)",
    attributes: ["dc", "distinguishedName", "msDS-Behavior-Version", "objectSid"],
  },
  USERS: {
    baseSuffix: "",
    filter: "(&(objectClass=user)(objectCategory=person))",
    attributes: ["sAMAccountName", "displayName", "userPrincipalName", "userAccountControl", "servicePrincipalName", "msDS-AllowedToDelegateTo", "lastLogon", "pwdLastSet", "objectSid"],
  },
  GROUPS: {
    baseSuffix: "",
    filter: "(objectClass=group)",
    attributes: ["sAMAccountName", "name", "member", "groupType", "objectSid"],
  },
  COMPUTERS: {
    baseSuffix: "",
    filter: "(objectClass=computer)",
    attributes: ["dNSHostName", "name", "operatingSystem", "operatingSystemVersion", "msDS-AllowedToDelegateTo", "objectSid"],
  },
  TRUSTS: {
    baseSuffix: "CN=System,",
    filter: "(objectClass=trustedDomain)",
    attributes: ["trustPartner", "trustDirection", "trustType", "trustAttributes", "securityIdentifier"],
  },
  PASSWORD_POLICY: {
    baseSuffix: "",
    filter: "(objectClass=domain)",
    attributes: ["minPwdLength", "lockoutThreshold", "maxPwdAge", "pwdProperties"],
  },
  GPO_METADATA: {
    baseSuffix: "CN=Policies,CN=System,",
    filter: "(objectClass=groupPolicyContainer)",
    attributes: ["displayName", "gPCFileSysPath", "versionNumber", "objectGUID"],
  },
};

/** Build the search base DN for a domain from a governed template:
 *  `CN=System,` + `DC=corp,DC=example` — the domain part comes from the
 *  registered domain, validated as DNS labels, never raw input. */
export function buildLdapBaseDn(domainDnsName: string, kind: LdapQueryKind): string {
  if (!/^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/.test(domainDnsName)) {
    throw new AdapterConfigurationError(`invalid domain DNS name for LDAP base construction: ${domainDnsName}`);
  }
  const domainPart = domainDnsName.split(".").map((label) => `DC=${label}`).join(",");
  return `${LDAP_QUERY_TEMPLATES[kind].baseSuffix}${domainPart}`;
}
