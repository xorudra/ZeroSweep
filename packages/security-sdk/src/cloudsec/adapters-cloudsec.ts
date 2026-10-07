/**
 * Prompt 14 — cloud-security adapters & connectors (§21–§35).
 *
 * Provider inventory connectors (AWS/Azure/GCP) collect read-only
 * metadata through injected transports; Prowler/ScoutSuite/Steampipe
 * run as governed CLI adapters; CloudMapper/ROADtools are import
 * connectors over recorded exports. Pacu intentionally has NO adapter
 * class (§34): offensive tooling is registered DISABLED in the tool
 * catalog and never executes in this phase.
 *
 * Every adapter resolves its target as a registered CloudAccount id
 * from worker-derived config. Targets are never URLs, credentials are
 * never accepted inline — only a credential REFERENCE name may ride
 * in plan config, resolved inside the CLOUD_ANALYSIS worker (§6/§11).
 * Transports expose no mutating method at all (§93).
 */
import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ExecutionPlan } from "../execution/execution.types";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import type { ToolRunner } from "../recon/runner";
import { assertCloudConfig, CloudSecAdapterBase, configStr, configStrList } from "./cloudsec-adapter.base";
import { normalizeProviderInventory, type CloudConnectorDeps } from "./inventory";
import {
  emptyParsedCloudSec, evaluateSteampipeQuery, parseCloudMapper, parseProwler, parseRoadtools,
  parseScoutSuite, parseSteampipeRows, type CloudSecParserContext, type ParsedCloudSec,
} from "./parsers-cloudsec";
import { EMPTY_CLOUD_SCOPE, type CloudProvider } from "./types";

function cloudSecMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "homepage" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "CLOUD",
    executionMode: "CONTAINER",
    riskLevel: "LOW",
    requiresApproval: false,
    supportedTargetTypes: ["AWS", "AZURE", "GCP"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 1800, maxTimeoutSeconds: 3600,
    resources: { cpu: "2", memory: "2Gi", timeoutSeconds: 1800 },
    inputSchema: [
      { name: "cloudAccountId", type: "string", description: "Registered CloudAccount id resolved by the worker from the scan target — never client-supplied" },
      { name: "cloudAccountRef", type: "string", description: "Provider-side account reference (account id / subscription / project) for fingerprints" },
      { name: "cloudProvider", type: "string", description: "AWS | AZURE | GCP — worker-derived from the registered account" },
      { name: "credentialReference", type: "string", description: "Secret-manager reference NAME only (§6); the value is resolved inside the CLOUD_ANALYSIS worker and never stored in the plan" },
      { name: "regions", type: "string[]", description: "Regions in scope for this scan (account scope ∩ scan scope)" },
      { name: "excludeRegions", type: "string[]", description: "Regions excluded by the account scope" },
    ],
    ...partial,
  } as ToolMetadata;
}

// ── Provider inventory connectors (§16–§19) ──────────────────────────

abstract class ProviderInventoryConnector extends BaseSecurityToolAdapter {
  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  protected constructor(
    protected readonly provider: CloudProvider,
    private readonly deps: CloudConnectorDeps,
  ) {
    super();
  }

  abstract override readonly metadata: ToolMetadata;

  async checkAvailability(): Promise<boolean> {
    return true; // per-account NOT_CONFIGURED is resolved at execute time (§9)
  }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: `${this.metadata.name} health is per-account: NOT_CONFIGURED until an account is registered and validated (§9)` };
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
    const accountId = configStr(config, "cloudAccountId");
    if (!accountId) throw new AdapterUnavailableError(`${this.metadata.slug}: no cloud account is registered for this scan — connector reports NOT_CONFIGURED (§9)`);
    const account = await this.deps.accounts.getById(accountId);
    if (!account) throw new AdapterUnavailableError(`${this.metadata.slug}: cloud account ${accountId} no longer exists — NOT_CONFIGURED`);
    if (account.provider !== this.provider) {
      throw new AdapterConfigurationError(`${this.metadata.slug}: account ${accountId} is a ${account.provider} account; this connector serves ${this.provider}`);
    }
    const transport = this.deps.transports[this.provider];
    if (!transport) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: no ${this.provider} transport is configured in this worker — account reports NOT_CONFIGURED (§9)`);
    }
    const includeRegions = configStrList(config, "regions");
    const scope = {
      ...EMPTY_CLOUD_SCOPE,
      ...(includeRegions.length > 0 ? { includeRegions } : {}),
      excludeRegions: configStrList(config, "excludeRegions"),
    };
    const raw = await transport.fetchInventory(account, scope);
    const data = normalizeProviderInventory(this.provider, raw, {
      accountId: account.id, accountRef: account.externalAccountId, scope, toolSlug: this.metadata.slug,
    });
    // Inventory ONLY (§14/§86): findings are produced by the platform
    // analysis stages over the persisted inventory — the same split
    // the source/container pipelines use — so section stages, retests
    // and compliance all reason over one canonical inventory.
    const payload: ParsedCloudSec = {
      findings: [],
      cloud: {
        resources: data.resources, identities: data.identities, relationships: data.relationships,
        controlAssessments: [], snapshot: data.snapshot, riskPaths: [],
        outOfScopeResources: data.outOfScope,
      },
      metrics: {
        resources: data.resources.length, identities: data.identities.length,
        relationships: data.relationships.length, outOfScopeResources: data.outOfScope.length,
      },
    };
    this.lastRaw = JSON.stringify(payload);
    return { rawOutput: this.lastRaw };
  }

  async parse(raw: string): Promise<ParsedCloudSec> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedCloudSec();
    try { return JSON.parse(text) as ParsedCloudSec; } catch { return emptyParsedCloudSec(); }
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCloudSec;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [],
      ...(p.cloud ? { cloud: p.cloud } : {}),
      artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    assertCloudConfig(config);
    this.pendingConfig = config;
  }
}

export class AwsInventoryConnector extends ProviderInventoryConnector {
  override readonly metadata = cloudSecMeta({
    id: "aws-inventory", slug: "aws-inventory", name: "AWS Inventory Connector",
    description: "Read-only AWS inventory + provider-native posture analysis (§16): account structure, IAM, network, storage, encryption and logging metadata. No data-plane access, no mutations (§7/§13).",
    homepage: "https://aws.amazon.com", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["CLOUD_INVENTORY", "CLOUD_POSTURE", "IDENTITY_INVENTORY", "RELATIONSHIP_ANALYSIS"],
  });
  constructor(deps: CloudConnectorDeps) { super("AWS", deps); }
}

export class AzureInventoryConnector extends ProviderInventoryConnector {
  override readonly metadata = cloudSecMeta({
    id: "azure-inventory", slug: "azure-inventory", name: "Azure Inventory Connector",
    description: "Read-only Azure inventory + provider-native posture analysis (§17): subscriptions, resource groups, NSGs, storage, RBAC metadata. No data-plane access, no mutations (§7/§13).",
    homepage: "https://azure.microsoft.com", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["CLOUD_INVENTORY", "CLOUD_POSTURE", "IDENTITY_INVENTORY", "RELATIONSHIP_ANALYSIS"],
  });
  constructor(deps: CloudConnectorDeps) { super("AZURE", deps); }
}

export class GcpInventoryConnector extends ProviderInventoryConnector {
  override readonly metadata = cloudSecMeta({
    id: "gcp-inventory", slug: "gcp-inventory", name: "GCP Inventory Connector",
    description: "Read-only GCP inventory + provider-native posture analysis (§18): organization/folder/project structure, firewall, storage, IAM metadata. No data-plane access, no mutations (§7/§13).",
    homepage: "https://cloud.google.com", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["CLOUD_INVENTORY", "CLOUD_POSTURE", "IDENTITY_INVENTORY", "RELATIONSHIP_ANALYSIS"],
  });
  constructor(deps: CloudConnectorDeps) { super("GCP", deps); }
}

// ── Prowler (§23/§24) ────────────────────────────────────────────────

export class ProwlerAdapter extends CloudSecAdapterBase {
  readonly metadata = cloudSecMeta({
    id: "prowler", slug: "prowler", name: "Prowler",
    description: "Prowler CSPM (§23): multi-cloud CIS/posture checks. FAIL results become findings on canonical cloud rules; PASS results are posture evidence only, never findings.",
    homepage: "https://github.com/prowler-cloud/prowler", licenseType: "OPEN_SOURCE",
    capabilities: ["CSPM", "CLOUD_POSTURE", "COMPLIANCE_QUERY"],
  });
  readonly executable = "prowler";
  readonly containerImage = "toniblyx/prowler:latest";
  readonly versionArgs = ["--version"];
  protected override readonly acceptableExitCodes: readonly number[] = [0, 3]; // 3 = checks failed (§38 classification)

  constructor(runner?: ToolRunner) { super(runner); }

  protected cloudSecPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const provider = configStr(config, "cloudProvider") ?? "AWS";
    const providerArg = provider === "AZURE" ? "azure" : provider === "GCP" ? "gcp" : "aws";
    return { args: [providerArg, "--output-formats", "json", "--no-banner", "--log-level", "ERROR"] };
  }
  protected parseCloudSec(text: string, ctx: CloudSecParserContext): ParsedCloudSec {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { return emptyParsedCloudSec(); }
    return { findings: parseProwler(parsed, ctx), metrics: {} };
  }
}

// ── ScoutSuite (§26) ─────────────────────────────────────────────────

export class ScoutSuiteAdapter extends CloudSecAdapterBase {
  readonly metadata = cloudSecMeta({
    id: "scoutsuite", slug: "scoutsuite", name: "ScoutSuite",
    description: "ScoutSuite multi-cloud auditing (§26): rule results become findings on the canonical cloud rules, merging with Prowler/native observations of the same issue (§60).",
    homepage: "https://github.com/nccgroup/ScoutSuite", licenseType: "OPEN_SOURCE",
    capabilities: ["CSPM", "CLOUD_POSTURE"],
  });
  readonly executable = "scout";
  readonly containerImage = "nccgroup/scoutsuite:latest";
  readonly versionArgs = ["--help"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected cloudSecPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const provider = configStr(config, "cloudProvider") ?? "AWS";
    const providerArg = provider === "AZURE" ? "azure" : provider === "GCP" ? "gcp" : "aws";
    return { args: [providerArg, "--no-browser"] };
  }
  protected parseCloudSec(text: string, ctx: CloudSecParserContext): ParsedCloudSec {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { return emptyParsedCloudSec(); }
    return { findings: parseScoutSuite(parsed, ctx), metrics: {} };
  }
}

// ── Steampipe (§32/§33) ──────────────────────────────────────────────

export class SteampipeAdapter extends CloudSecAdapterBase {
  readonly metadata = cloudSecMeta({
    id: "steampipe", slug: "steampipe", name: "Steampipe",
    description: "Steampipe governed query packs (§32): SQL-as-inventory through approved packs only — arbitrary SQL from users or repositories is refused at plan time.",
    homepage: "https://steampipe.io", licenseType: "OPEN_SOURCE",
    capabilities: ["CLOUD_QUERY", "CSPM"],
    inputSchema: [
      { name: "cloudAccountId", type: "string", description: "Registered CloudAccount id resolved by the worker" },
      { name: "cloudAccountRef", type: "string", description: "Provider-side account reference" },
      { name: "cloudProvider", type: "string", description: "AWS | AZURE | GCP" },
      { name: "credentialReference", type: "string", description: "Secret-manager reference NAME only (§6)" },
      { name: "queryPack", type: "string", description: "Approved query pack id (§32) — required; arbitrary SQL is never accepted" },
      { name: "sql", type: "string", description: "MUST be empty: present only so arbitrary SQL can be explicitly refused (§32)" },
    ],
  });
  readonly executable = "steampipe";
  readonly containerImage = "turbot/steampipe:latest";
  readonly versionArgs = ["--version"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected cloudSecPlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const verdict = evaluateSteampipeQuery({
      ...(configStr(config, "queryPack") ? { packId: configStr(config, "queryPack")! } : {}),
      ...(configStr(config, "sql") ? { sql: configStr(config, "sql")! } : {}),
    });
    if (!verdict.allowed) throw new AdapterConfigurationError(verdict.reason ?? "steampipe query not allowed");
    return { args: ["check", verdict.packId!, "--output", "json"] };
  }
  protected parseCloudSec(text: string, ctx: CloudSecParserContext): ParsedCloudSec {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { return emptyParsedCloudSec(); }
    return { findings: parseSteampipeRows(parsed, ctx), metrics: {} };
  }
}

// ── Import connectors: CloudMapper (§27) + ROADtools (§29/§30) ──────

abstract class CloudImportConnector extends BaseSecurityToolAdapter {
  private pendingConfig: Record<string, unknown> | undefined;
  protected abstract importParse(text: string, ctx: CloudSecParserContext): ParsedCloudSec;
  protected abstract readonly importProvider: CloudProvider;

  async checkAvailability(): Promise<boolean> { return true; }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNAVAILABLE", detail: `${this.metadata.name}: import connector — fed by recorded exports in the worker artifact store; no live connection configured` };
  }

  async buildExecutionPlan(_target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "EXTERNAL_API",
      arguments: [], environmentReferences: [],
      timeoutSeconds: this.metadata.defaultTimeoutSeconds,
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "NO_NETWORK", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError(`${this.metadata.slug}: execute() called without buildExecutionPlan()`);
    if (!configStr(config, "cloudAccountId")) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: no cloud account is registered for this scan — NOT_CONFIGURED (§9)`);
    }
    throw new AdapterUnavailableError(`${this.metadata.slug}: no recorded export artifact is available in this worker — import connectors never fabricate data`);
  }

  async parse(raw: string): Promise<ParsedCloudSec> {
    if (!raw) return emptyParsedCloudSec();
    const c = this.pendingConfig ?? {};
    return this.importParse(raw, {
      toolSlug: this.metadata.slug, provider: this.importProvider,
      ...(configStr(c, "cloudAccountId") ? { accountId: configStr(c, "cloudAccountId")! } : {}),
      ...(configStr(c, "cloudAccountRef") ? { accountRef: configStr(c, "cloudAccountRef")! } : {}),
    });
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCloudSec;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [], artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    assertCloudConfig(config);
    this.pendingConfig = config;
  }
}

export class CloudMapperConnector extends CloudImportConnector {
  readonly metadata = cloudSecMeta({
    id: "cloudmapper", slug: "cloudmapper", name: "CloudMapper",
    description: "CloudMapper (AWS) account-graph import (§27): public nodes and network structure become exposure evidence in the asset graph.",
    homepage: "https://github.com/duo-labs/cloudmapper", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["AWS_NETWORK_ANALYSIS", "AWS_ACCOUNT_VISUALIZATION", "PUBLIC_EXPOSURE_ANALYSIS"],
  });
  protected readonly importProvider: CloudProvider = "AWS";
  protected importParse(text: string, ctx: CloudSecParserContext): ParsedCloudSec {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { return emptyParsedCloudSec(); }
    const { findings, publicNodes } = parseCloudMapper(parsed, ctx);
    return { findings, metrics: { publicNodes: publicNodes.length } };
  }
}

export class RoadtoolsConnector extends CloudImportConnector {
  readonly metadata = cloudSecMeta({
    id: "roadtools", slug: "roadtools", name: "ROADtools",
    description: "ROADtools (Entra ID) DEFENSIVE analysis (§29/§30): role assignments, application permissions and risky relationships from recorded exports. Offensive directory operations are never invoked (§106).",
    homepage: "https://github.com/dirkjanm/ROADtools", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API", supportsContainerExecution: false,
    capabilities: ["DIRECTORY_ANALYSIS", "IDENTITY_INVENTORY"],
  });
  protected readonly importProvider: CloudProvider = "AZURE";
  protected importParse(text: string, ctx: CloudSecParserContext): ParsedCloudSec {
    let parsed: unknown;
    try { parsed = JSON.parse(text); } catch { return emptyParsedCloudSec(); }
    return { findings: parseRoadtools(parsed, ctx), metrics: {} };
  }
}

/** Connector deps type re-export for worker/API wiring. */
export type { CloudConnectorDeps };
