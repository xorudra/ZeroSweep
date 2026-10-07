/**
 * Prompt 15 — Active Directory adapters (§13/§27/§38/§41/§44/§48).
 *
 * DEFENSIVE ONLY. The connectors collect/import directory data through
 * the read-only transport (§15); the CLI adapters run governed,
 * typed plans: ldapsearch with platform-generated filters (§14),
 * SharpHound with policy-classified collection methods (§29),
 * PingCastle healthcheck (§38), enum4linux-ng service/share inventory
 * (§41), SMBMap share/permissions inventory with NO content capability
 * (§44), and Certipy in FIND (posture) mode only (§48). The offensive
 * tools (NetExec offensive, Impacket, Kerbrute, Responder, PowerView
 * offensive, Certipy offensive) have NO adapters — they exist as
 * DISABLED registry descriptors (types.ts) so policy can name them.
 */
import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { ExecutionPlan } from "../execution/execution.types";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolRunner } from "../recon/runner";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import {
  DirectoryAdapterBase, assertDirectoryConfig, buildLdapBaseDn, dirConfigStr as configStr, dirConfigStrList as configStrList,
  emptyParsedDirectory, LDAP_QUERY_KINDS, LDAP_QUERY_TEMPLATES,
  type DirectoryParserContext, type LdapQueryKind, type ParsedDirectory,
} from "./directory-adapter.base";
import type { DirectoryConnectorDeps, DirectoryCollectionKind } from "./inventory";
import { buildDirectorySnapshot, normalizeDirectoryCollection } from "./inventory";
import { clampDirectoryBudget, evaluateSharpHoundCollectionPolicy } from "./types";
import {
  parseBloodHoundExport, parseCertipyFind, parseDirectoryPayload, parseEnum4linuxNgOutput,
  parseLdapEntries, parsePingCastleReport, parseSmbMapOutput,
} from "./parsers-directory";
import { analyzeAdcsPosture } from "./analysis";
import { sanitizeDirectoryText } from "./guards";

function directoryMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "homepage" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "ACTIVE_DIRECTORY",
    executionMode: "CONTAINER",
    riskLevel: "LOW",
    requiresApproval: false,
    supportedTargetTypes: ["ACTIVE_DIRECTORY", "ACTIVE_DIRECTORY_DOMAIN", "ACTIVE_DIRECTORY_FOREST", "DOMAIN_CONTROLLER", "LDAP_DIRECTORY"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 1800, maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 1800 },
    requiredWorkerType: "DIRECTORY_ANALYSIS",
    inputSchema: [
      { name: "directoryDomainId", type: "string", description: "Registered ActiveDirectoryDomain id resolved by the worker from the scan target — never client-supplied" },
      { name: "directoryDomainRef", type: "string", description: "Domain DNS name (fingerprint component) — worker-derived from the registered domain" },
      { name: "credentialReference", type: "string", description: "Secret-manager reference NAME only (§7); the value is resolved inside the DIRECTORY_ANALYSIS worker and never stored in the plan" },
      { name: "dcHosts", type: "string[]", description: "Explicitly approved domain controllers for this domain (§11) — worker-derived" },
      { name: "collectionMethods", type: "string[]", description: "SharpHound collection methods — validated through the §29 policy (SAFE by default)" },
      { name: "queryKind", type: "string", description: "Governed LDAP query kind (§14) — filters are platform-generated; arbitrary filters are refused" },
      { name: "artifactFormat", type: "string", description: "Import format for staged collector artifacts (bloodhound-json | pingcastle-xml | adexplorer-json | ldap-json)" },
      { name: "artifactText", type: "string", description: "Staged collector artifact content for manual imports — staged by the API/worker from protected storage, never client-supplied inline (§30)" },
      { name: "allowReviewRequiredCollection", type: "boolean", description: "Administrator approval of the §29 REVIEW_REQUIRED SharpHound collection set (sessions/local access) — default false" },
    ],
    ...partial,
  } as ToolMetadata;
}

// ── Directory collection connectors (§13/§15/§27) ────────────────────

abstract class DirectoryCollectionConnector extends BaseSecurityToolAdapter {
  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  protected constructor(
    private readonly deps: DirectoryConnectorDeps,
    private readonly kind: DirectoryCollectionKind,
    private readonly transportKey: string,
  ) {
    super();
  }

  abstract override readonly metadata: ToolMetadata;

  async checkAvailability(): Promise<boolean> {
    return true; // per-domain NOT_CONFIGURED is resolved at execute time
  }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: `${this.metadata.name} health is per-domain: NOT_CONFIGURED until a domain is registered with a reachable read-only transport (§15)` };
  }

  async buildExecutionPlan(_target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "EXTERNAL_API",
      arguments: [], environmentReferences: [],
      timeoutSeconds: this.metadata.defaultTimeoutSeconds,
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError(`${this.metadata.slug}: execute() called without buildExecutionPlan()`);
    const domainId = configStr(config, "directoryDomainId");
    if (!domainId) throw new AdapterUnavailableError(`${this.metadata.slug}: no directory domain is registered for this scan — connector reports NOT_CONFIGURED (§15)`);
    const domain = await this.deps.domains.getDomain(domainId);
    if (!domain) throw new AdapterUnavailableError(`${this.metadata.slug}: directory domain ${domainId} no longer exists — NOT_CONFIGURED`);

    // Manual import path (§28/§31/§56): a staged collector artifact is
    // parsed locally — no directory is contacted at all.
    const artifactText = configStr(config, "artifactText");
    if (artifactText) {
      const format = configStr(config, "artifactFormat") ?? "bloodhound-json";
      const parsed = parseDirectoryPayload(artifactText, format === "adexplorer-json" ? "bloodhound-json" : format, {
        domainDnsName: domain.dnsName, domainId: domain.id, source: this.metadata.slug,
        includeSessions: configStrList(config, "collectionMethods").includes("SESSIONS"),
        includeLocalAdmins: true,
      });
      const { data } = normalizeDirectoryCollection(parsed, clampDirectoryBudget());
      const snapshot = buildDirectorySnapshot(data, {
        collectionProfile: `${this.metadata.slug}:${format}`,
        collectorVersions: { [this.metadata.slug]: this.metadata.adapterVersion },
      });
      const payload: ParsedDirectory = {
        findings: parsed.findings,
        directory: { ...data, snapshot },
        metrics: {
          users: data.users.length, groups: data.groups.length, computers: data.computers.length,
          relationships: data.relationships.length, findings: parsed.findings.length,
        },
      };
      this.lastRaw = JSON.stringify(payload);
      return { rawOutput: this.lastRaw };
    }

    const transport = this.deps.transports[this.transportKey];
    if (!transport) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: no directory transport is configured in this worker — domain reports NOT_CONFIGURED (§15)`);
    }
    const methods = configStrList(config, "collectionMethods");
    if (methods.length > 0) {
      const verdict = evaluateSharpHoundCollectionPolicy(methods);
      if (!verdict.allowed) {
        throw new AdapterConfigurationError(
          `${this.metadata.slug}: collection policy denied: ${verdict.denied.map((d) => `${d.method} (${d.classification})`).join(", ")} (§29)`,
        );
      }
    }
    const collected = await transport.collect({
      domain, kind: this.kind, budget: clampDirectoryBudget(),
      ...(methods.length > 0 ? { collectionMethods: methods } : {}),
    });
    if (collected.mutationCalls.length > 0) {
      // Structural invariant (§83): a transport that reports a mutation
      // attempt fails the collection loudly — data is discarded.
      throw new AdapterConfigurationError(`${this.metadata.slug}: transport reported mutation attempts (${collected.mutationCalls.join(", ")}) — collection discarded (§83)`);
    }
    const { data } = normalizeDirectoryCollection(collected.data, clampDirectoryBudget());
    const snapshot = buildDirectorySnapshot(data, {
      collectionProfile: this.kind,
      collectorVersions: collected.collectorVersions,
    });
    const payload: ParsedDirectory = {
      findings: [],
      directory: { ...data, snapshot },
      metrics: {
        users: data.users.length, groups: data.groups.length, computers: data.computers.length,
        domainControllers: data.domainControllers.length, relationships: data.relationships.length,
        trusts: data.trusts.length, sessionsDropped: collected.sessionsDropped,
      },
    };
    this.lastRaw = JSON.stringify(payload);
    return { rawOutput: this.lastRaw };
  }

  async parse(raw: string): Promise<ParsedDirectory> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedDirectory();
    try { return JSON.parse(text) as ParsedDirectory; } catch { return emptyParsedDirectory(); }
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedDirectory;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      ...(p.directory ? { directory: p.directory } : {}),
      artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertDirectoryConfig(config);
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

/** §13/§15: the governed LDAP collection connector. */
export class LdapDirectoryConnector extends DirectoryCollectionConnector {
  override readonly metadata = directoryMeta({
    id: "ldap-directory-connector", slug: "ldap-directory-connector", name: "LDAP Directory Connector",
    description: "Governed read-only LDAP collection (§13–§17): paged inventory of users, groups, computers, OUs, GPO metadata, trusts and password-policy metadata over LDAPS. Never collects passwords or credential material (§19); only approved DCs are contacted (§11).",
    homepage: "https://www.openldap.org", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["DIRECTORY_INVENTORY", "LDAP_SECURITY_ANALYSIS", "IDENTITY_RELATIONSHIP_DISCOVERY"],
  });
  constructor(deps: DirectoryConnectorDeps) { super(deps, "DIRECTORY_INVENTORY", "ldap"); }
}

/** §27: BloodHound is graph + analysis infrastructure here — the
 *  connector imports collector datasets and SharpHound collections;
 *  it never executes an attack path. */
export class BloodHoundConnector extends DirectoryCollectionConnector {
  override readonly metadata = directoryMeta({
    id: "bloodhound-connector", slug: "bloodhound-connector", name: "BloodHound Connector",
    description: "BloodHound graph import + defensive attack-path analysis (§27–§31): normalizes SharpHound/BloodHound exports (and ADExplorer snapshots) into the identity graph. Raw datasets are highly sensitive — protected storage, VIEW_RAW_DIRECTORY_GRAPH, audited access (§30). Attack paths are modeled, never executed (§34).",
    homepage: "https://github.com/SpecterOps/BloodHound", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["IDENTITY_GRAPH", "PRIVILEGE_RELATIONSHIP_ANALYSIS", "DEFENSIVE_ATTACK_PATH_ANALYSIS", "SNAPSHOT_IMPORT"],
  });
  constructor(deps: DirectoryConnectorDeps) { super(deps, "BLOODHOUND_IMPORT", "bloodhound"); }
}

// ── ldapsearch (§14) ─────────────────────────────────────────────────

/** Flags a governed ldapsearch plan may never contain: write
 *  operations and destructive controls are structurally absent. */
export const LDAPSEARCH_FORBIDDEN_FLAGS = ["-f", "--file"] as const;

export class LdapsearchAdapter extends DirectoryAdapterBase {
  readonly metadata = directoryMeta({
    id: "ldapsearch", slug: "ldapsearch", name: "ldapsearch",
    description: "OpenLDAP ldapsearch with TYPED, platform-generated queries only (§14): the caller picks a governed queryKind; filters and attribute lists come from the platform template catalog. Arbitrary LDAP filters from users or the frontend are refused at configuration validation.",
    homepage: "https://www.openldap.org", licenseType: "OPEN_SOURCE",
    capabilities: ["DIRECTORY_INVENTORY", "LDAP_SECURITY_ANALYSIS"],
  });
  readonly executable = "ldapsearch";
  readonly containerImage = "osixia/openldap:latest";
  readonly versionArgs = ["-VV"];

  constructor(runner?: ToolRunner) { super(runner); }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    const kind = configStr(config, "queryKind") ?? "DOMAIN_INFO";
    if (!(LDAP_QUERY_KINDS as readonly string[]).includes(kind)) {
      throw new AdapterConfigurationError(`ldapsearch queryKind "${kind}" is not a governed query kind (§14)`);
    }
  }

  protected directoryPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const kind = (configStr(config, "queryKind") ?? "DOMAIN_INFO") as LdapQueryKind;
    const domainRef = configStr(config, "directoryDomainRef") ?? "";
    const dcHost = configStrList(config, "dcHosts")[0] ?? "";
    const template = LDAP_QUERY_TEMPLATES[kind];
    const base = buildLdapBaseDn(domainRef, kind);
    // -x simple auth (identity resolved by the worker from the
    // credential reference), -LLL no LDIF comments/version, -z size
    // cap + -l time cap (§17 bounded responses), -E pr paged results.
    return {
      args: [
        "-x", "-LLL", "-H", `ldaps://${dcHost}`, "-b", base, "-s", "sub",
        "-z", "5000", "-l", "120", "-E", "pr=1000/noprompt",
        template.filter, ...template.attributes,
      ],
    };
  }

  protected parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory {
    const entries = parseLdif(text);
    const directory = parseLdapEntries(entries, { domainDnsName: ctx.domainRef, source: this.metadata.slug });
    return {
      findings: [],
      directory,
      metrics: {
        users: directory.users.length, groups: directory.groups.length,
        computers: directory.computers.length, trusts: directory.trusts.length,
      },
    };
  }
}

/** Minimal LDIF reader for ldapsearch output: entries separated by
 *  blank lines, `attr: value` pairs, continuation lines folded.
 *  Values stay STRINGS except known numeric attributes. */
export function parseLdif(text: string): Record<string, unknown>[] {
  const entries: Record<string, unknown>[] = [];
  let current: Record<string, unknown> | null = null;
  let lastKey = "";
  const flush = () => { if (current && Object.keys(current).length > 0) entries.push(current); current = null; };
  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.trim() === "") { flush(); lastKey = ""; continue; }
    if (rawLine.startsWith("#") || rawLine.startsWith("version:")) continue;
    if (rawLine.startsWith(" ") && current && lastKey) {
      const prev = current[lastKey];
      if (typeof prev === "string") current[lastKey] = prev + rawLine.slice(1);
      continue;
    }
    const idx = rawLine.indexOf(":");
    if (idx <= 0) continue;
    const key = rawLine.slice(0, idx).trim();
    let value: string = rawLine.slice(idx + 1).trim();
    if (value.startsWith(":")) value = value.slice(1).trim(); // base64 marker `::` — decoded values are out of scope; keep raw text
    if (!current) current = {};
    const numeric = /^(userAccountControl|lockoutThreshold|minPwdLength|groupType)$/i.test(key);
    const coerced: unknown = numeric && /^-?\d+$/.test(value) ? Number(value) : value;
    const existing = current[key];
    if (existing === undefined) current[key] = coerced;
    else if (Array.isArray(existing)) existing.push(coerced);
    else current[key] = [existing, coerced];
    lastKey = key;
    if (key.toLowerCase() === "dn" && typeof coerced === "string") current.dn = coerced;
  }
  flush();
  return entries;
}

// ── SharpHound (§28/§29) ─────────────────────────────────────────────

export class SharpHoundAdapter extends DirectoryAdapterBase {
  readonly metadata = directoryMeta({
    id: "sharphound", slug: "sharphound", name: "SharpHound",
    description: "SharpHound collection under the governed collection policy (§29): default automated collection is the SAFE inventory/relationship set; session and local-access methods are REVIEW_REQUIRED and refused without administrator approval; unknown methods are DISABLED. Collection runs only on approved internal DIRECTORY_ANALYSIS workers.",
    homepage: "https://github.com/SpecterOps/SharpHound", licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE", requiresApproval: true,
    capabilities: ["DIRECTORY_RELATIONSHIP_COLLECTION", "IDENTITY_GRAPH"],
  });
  readonly executable = "SharpHound";
  readonly containerImage = "specterops/sharphound:latest";
  readonly versionArgs = ["--help"];

  constructor(runner?: ToolRunner) { super(runner); }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    const methods = configStrList(config, "collectionMethods");
    if (methods.length > 0) {
      const verdict = evaluateSharpHoundCollectionPolicy(methods, {
        allowReviewRequired: config.allowReviewRequiredCollection === true,
      });
      if (!verdict.allowed) {
        throw new AdapterConfigurationError(
          `SharpHound collection policy denied: ${verdict.denied.map((d) => `${d.method}=${d.classification}`).join(", ")} — automated collection is limited to the SAFE set unless the REVIEW_REQUIRED set is administrator-approved (§29)`,
        );
      }
    }
  }

  protected directoryPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const methods = configStrList(config, "collectionMethods");
    const verdict = evaluateSharpHoundCollectionPolicy(
      methods.length > 0 ? methods : ["MEMBERSHIP", "ACL", "TRUSTS", "CONTAINER", "OBJECT_PROPERTIES"],
      { allowReviewRequired: config.allowReviewRequiredCollection === true },
    );
    const domainRef = configStr(config, "directoryDomainRef") ?? "";
    return {
      args: ["--collectionmethods", verdict.approved.join(","), "--domain", domainRef, "--zipfilename", "sharphound-collection.zip"],
    };
  }

  protected parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory {
    let json: unknown;
    try { json = JSON.parse(text); } catch { return emptyParsedDirectory(); }
    const { directory, counts, sessionsDropped } = parseBloodHoundExport(json, {
      domainDnsName: ctx.domainRef, source: this.metadata.slug,
      includeSessions: false, includeLocalAdmins: true,
    });
    return { findings: [], directory, metrics: { ...counts, sessionsDropped } };
  }
}

// ── PingCastle (§38) ─────────────────────────────────────────────────

export class PingCastleAdapter extends DirectoryAdapterBase {
  readonly metadata = directoryMeta({
    id: "pingcastle", slug: "pingcastle", name: "PingCastle",
    description: "PingCastle AD healthcheck import (§38): rule results normalize onto canonical AD rules (merging with native analysis, §109) with category, evidence and remediation. The PingCastle score is preserved SEPARATELY from the DSRclone risk score (§39). Healthcheck mode only.",
    homepage: "https://www.pingcastle.com", licenseType: "COMMERCIAL",
    capabilities: ["AD_SECURITY_POSTURE", "DOMAIN_CONFIGURATION_REVIEW", "AD_RISK_ASSESSMENT"],
    inputSchema: [
      { name: "directoryDomainId", type: "string", description: "Registered ActiveDirectoryDomain id — worker-derived" },
      { name: "directoryDomainRef", type: "string", description: "Domain DNS name — worker-derived" },
      { name: "credentialReference", type: "string", description: "Secret reference NAME only (§7)" },
      { name: "dcHosts", type: "string[]", description: "Approved DCs (§11) — worker-derived" },
      { name: "mode", type: "string", description: "healthcheck only — any other mode is refused (§38)" },
    ],
  });
  readonly executable = "PingCastle";
  readonly containerImage = "pingcastle/pingcastle:latest";
  readonly versionArgs = ["--help"];

  constructor(runner?: ToolRunner) { super(runner); }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    const mode = configStr(config, "mode");
    if (mode !== undefined && mode !== "healthcheck") {
      throw new AdapterConfigurationError(`PingCastle mode "${mode}" is not permitted: healthcheck mode only (§38)`);
    }
  }

  protected directoryPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const dcHost = configStrList(config, "dcHosts")[0] ?? "";
    return { args: ["--healthcheck", "--server", dcHost] };
  }

  protected parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory {
    const result = parsePingCastleReport(text, {
      domainDnsName: ctx.domainRef, ...(ctx.domainId ? { domainId: ctx.domainId } : {}), source: this.metadata.slug,
    });
    return {
      findings: result.findings,
      metrics: {
        rules: result.rules.length, findings: result.findings.length,
        ...(result.pingcastleScore !== undefined ? { pingcastleScore: result.pingcastleScore } : {}),
      },
    };
  }
}

// ── enum4linux-ng (§41) ──────────────────────────────────────────────

export class Enum4linuxNgAdapter extends DirectoryAdapterBase {
  readonly metadata = directoryMeta({
    id: "enum4linux-ng", slug: "enum4linux-ng", name: "enum4linux-ng",
    description: "enum4linux-ng service/share/policy enumeration (§41): SMB protocol metadata (dialect, signing), share lists and domain policy facts for AUTHORIZED hosts only. No credential guessing exists anywhere in the flow (§120).",
    homepage: "https://github.com/cddmp/enum4linux-ng", licenseType: "OPEN_SOURCE",
    supportedTargetTypes: ["ACTIVE_DIRECTORY", "ACTIVE_DIRECTORY_DOMAIN", "DOMAIN_CONTROLLER"],
    capabilities: ["SMB_DIRECTORY_ENUMERATION", "WINDOWS_SERVICE_DISCOVERY"],
  });
  readonly executable = "enum4linux-ng";
  readonly containerImage = "enum4linux-ng:latest";
  readonly versionArgs = ["--help"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected directoryPlan(target: AdapterTarget, _config: Record<string, unknown>): ReconPlanParts {
    // -U users, -G groups, -S shares, -P password policy, -oJ JSON out.
    // Deliberately NO -a (all incl. RID cycling/brute options).
    return { args: ["-U", "-G", "-S", "-P", "-oJ", "enum4linux-ng", target.value] };
  }

  protected parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory {
    let json: unknown;
    try { json = JSON.parse(text); } catch { return emptyParsedDirectory(); }
    const { shares, services } = parseEnum4linuxNgOutput(json, { domainDnsName: ctx.domainRef, source: this.metadata.slug });
    return {
      findings: [],
      directory: {
        domainControllers: [], users: [], groups: [], computers: [], organizationalUnits: [],
        groupPolicies: [], trusts: [], relationships: [], smbShares: shares,
        certificateAuthorities: [], certificateTemplates: [],
      },
      metrics: { smbShares: shares.length, services: services.length },
    };
  }
}

// ── SMBMap (§42–§44) ─────────────────────────────────────────────────

/** Flags the governed SMBMap plan can NEVER emit (§44): no download,
 *  no upload, no command execution, no recursive listing, no content
 *  search — inventory and permission review only. */
export const SMBMAP_FORBIDDEN_FLAGS = ["-d", "--download", "-u", "--upload", "-x", "--execute", "-r", "--recursive", "--search"] as const;

export function buildSmbMapArgs(host: string): string[] {
  return ["-H", host, "-P", "445", "-q"];
}

export class SmbMapAdapter extends DirectoryAdapterBase {
  readonly metadata = directoryMeta({
    id: "smbmap", slug: "smbmap", name: "SMBMap",
    description: "SMBMap share + permission INVENTORY (§42–§44): share names and access classification only. The governed plan has no code path to download, upload, execute or content-search — share contents are never fetched (§97).",
    homepage: "https://github.com/ShawnDEvans/smbmap", licenseType: "OPEN_SOURCE",
    supportedTargetTypes: ["ACTIVE_DIRECTORY", "ACTIVE_DIRECTORY_DOMAIN", "DOMAIN_CONTROLLER"],
    capabilities: ["SMB_SHARE_INVENTORY", "SMB_PERMISSION_REVIEW"],
  });
  readonly executable = "smbmap";
  readonly containerImage = "smbmap:latest";
  readonly versionArgs = ["--help"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected directoryPlan(target: AdapterTarget, _config: Record<string, unknown>): ReconPlanParts {
    return { args: buildSmbMapArgs(target.value) };
  }

  protected parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory {
    let json: unknown;
    try { json = JSON.parse(text); } catch { return emptyParsedDirectory(); }
    const { shares } = parseSmbMapOutput(json, { domainDnsName: ctx.domainRef, source: this.metadata.slug });
    return {
      findings: [],
      directory: {
        domainControllers: [], users: [], groups: [], computers: [], organizationalUnits: [],
        groupPolicies: [], trusts: [], relationships: [], smbShares: shares,
        certificateAuthorities: [], certificateTemplates: [],
      },
      metrics: { smbShares: shares.length },
    };
  }
}

// ── Certipy posture (§47–§50) ────────────────────────────────────────

/** Actions Certipy supports that this platform will NEVER run (§48):
 *  requesting certificates for exploitation, authenticating as another
 *  identity, forging, relaying or shadow-credential operations. */
export const CERTIPY_FORBIDDEN_ACTIONS = ["req", "auth", "forge", "relay", "shadow", "account", "ca", "template-write", "esc1", "esc8"] as const;

export class CertipyPostureAdapter extends DirectoryAdapterBase {
  readonly metadata = directoryMeta({
    id: "certipy-posture", slug: "certipy-posture", name: "Certipy (posture)",
    description: "Certipy AD CS posture adapter (§47–§50): FIND (inventory/posture) ONLY — CA/template configuration metadata normalized and classified into governed ESC-style risk classes. It never requests certificates, never authenticates as another identity, and the offensive capability (ADCS_OFFENSIVE_VALIDATION) is DISABLED with no implementation.",
    homepage: "https://github.com/ly4k/Certipy", licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE", requiresApproval: true,
    capabilities: ["ADCS_INVENTORY", "ADCS_POSTURE_ANALYSIS"],
    inputSchema: [
      { name: "directoryDomainId", type: "string", description: "Registered ActiveDirectoryDomain id — worker-derived" },
      { name: "directoryDomainRef", type: "string", description: "Domain DNS name — worker-derived" },
      { name: "credentialReference", type: "string", description: "Secret reference NAME only (§7)" },
      { name: "dcHosts", type: "string[]", description: "Approved DCs (§11) — worker-derived" },
      { name: "action", type: "string", description: "find only — request/auth/forge/relay/shadow actions are refused (§48)" },
    ],
  });
  readonly executable = "certipy";
  readonly containerImage = "certipy:latest";
  readonly versionArgs = ["--help"];

  constructor(runner?: ToolRunner) { super(runner); }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    const action = (configStr(config, "action") ?? "find").toLowerCase();
    if (action !== "find") {
      throw new AdapterConfigurationError(
        `Certipy action "${action}" is refused: the posture adapter runs FIND (inventory/posture) only — certificate requests, alternate-identity authentication, forging, relay and shadow operations are DISABLED (§47/§48/§120)`,
      );
    }
  }

  protected directoryPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const dcHost = configStrList(config, "dcHosts")[0] ?? "";
    return { args: ["find", "-json", "-output", "certipy-find", "-dc-ip", dcHost] };
  }

  protected parseDirectory(text: string, ctx: DirectoryParserContext): ParsedDirectory {
    let json: unknown;
    try { json = JSON.parse(text); } catch { return emptyParsedDirectory(); }
    const parsed = parseCertipyFind(json, { domainDnsName: ctx.domainRef, source: this.metadata.slug });
    const directory = {
      domainControllers: [], users: [], groups: [], computers: [], organizationalUnits: [],
      groupPolicies: [], trusts: [], relationships: [], smbShares: [],
      certificateAuthorities: parsed.certificateAuthorities, certificateTemplates: parsed.certificateTemplates,
    };
    const adcs = analyzeAdcsPosture(directory, {
      domainRef: ctx.domainRef, ...(ctx.domainId ? { domainId: ctx.domainId } : {}), toolSlug: this.metadata.slug,
    });
    const templates = parsed.certificateTemplates.map((t) => ({
      ...t, riskClasses: adcs.templateRiskClasses.get(t.name) ?? [],
    }));
    return {
      findings: adcs.findings,
      directory: { ...directory, certificateTemplates: templates },
      metrics: {
        certificateAuthorities: parsed.certificateAuthorities.length,
        certificateTemplates: parsed.certificateTemplates.length,
        findings: adcs.findings.length,
      },
    };
  }
}

/** Sanitize helper re-export for adapter tests. */
export { sanitizeDirectoryText };
