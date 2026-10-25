import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { emptyParsedProxy, type ParsedProxy } from "../proxy/parsers-proxy";
import type { ConnectorDeps } from "../proxy/connector";
import type { ScannerInstanceRecord } from "../proxy/types";
import {
  CONNECTOR_INPUT_SCHEMA, scopeRulesFromConfig, type ConnectorEnvelope,
} from "../proxy/adapters-proxy";
import { generateScannerTargets, type VulnerabilityScannerConnector } from "./scanners";
import { GreenboneConnector, NessusConnector } from "./scanners";

export const VULN_SCANNER_SLUGS = ["greenbone-openvas", "nessus-professional"] as const;

/**
 * Worker adapters for the Prompt 11 vulnerability scanners (§84). The
 * execution flow is the connector task lifecycle — resolve the admin-
 * registered instance → health → create a scan task with SCOPE-DERIVED
 * targets and an administrator-mapped LOGICAL profile → poll (bounded)
 * → fetch + parse the report → normalize. There is no command, no
 * container and no arbitrary request surface.
 *
 * Honesty (§85/§86): no instance → NOT_CONFIGURED; unreachable scanner →
 * UNAVAILABLE; in both cases the adapter throws AdapterUnavailableError
 * and the stage degrades (SKIPPED/PARTIAL) — a scanner that did not run
 * never produces findings.
 */
export class VulnScannerAdapter extends BaseSecurityToolAdapter {
  readonly metadata: ToolMetadata;
  private lastEnvelope: (ConnectorEnvelope & { checksum?: string }) | undefined;
  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  constructor(
    readonly connector: VulnerabilityScannerConnector,
    private readonly deps: ConnectorDeps,
    metadata: ToolMetadata,
    private readonly poll: { maxPolls?: number; intervalMs?: number; sleep?: (ms: number) => Promise<void> } = {},
  ) {
    super();
    this.metadata = metadata;
  }

  private async instance(instanceId?: string): Promise<ScannerInstanceRecord | null> {
    if (instanceId) return this.deps.instances.getById(instanceId);
    const enabled = await this.deps.instances.listEnabled(this.connector.product);
    return enabled[0] ?? null;
  }

  async checkAvailability(): Promise<boolean> {
    const instance = await this.instance();
    if (!instance || !instance.enabled) return false;
    const health = await this.connector.healthCheck(instance);
    return health.status === "HEALTHY" || health.status === "DEGRADED";
  }

  override async healthCheck(): Promise<{ status: string; detail?: string }> {
    const instance = await this.instance();
    if (!instance) {
      return {
        status: "NOT_CONFIGURED",
        detail: this.connector.product === "NESSUS"
          ? "Nessus Professional is not configured — an administrator-provided licensed instance is required (§85). This is a configuration state, not a platform failure."
          : "No Greenbone/OpenVAS instance is registered — an administrator must register one (§3).",
      };
    }
    const health = await this.connector.healthCheck(instance);
    return {
      status: health.status,
      detail: [health.detail, health.version ? `version ${health.version}` : undefined, health.licenseState ? `license: ${health.licenseState}` : undefined].filter(Boolean).join(" — "),
    };
  }

  async buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    void target;
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: this.metadata.executionMode,
      arguments: [], environmentReferences: [],
      timeoutSeconds: Math.min(typeof config.timeoutSeconds === "number" ? config.timeoutSeconds : this.metadata.defaultTimeoutSeconds, this.metadata.maxTimeoutSeconds),
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    void plan;
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError(`${this.metadata.slug}: execute() called without buildExecutionPlan()`);
    const instanceId = typeof config.instanceId === "string" ? config.instanceId : undefined;
    if (!instanceId) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: no scanner instance is configured for this workspace — connector reports NOT_CONFIGURED (§85/§86)`);
    }
    const instance = await this.instance(instanceId);
    if (!instance) throw new AdapterUnavailableError(`${this.metadata.slug}: scanner instance ${instanceId} no longer exists`);
    const health = await this.connector.healthCheck(instance);
    if (health.status !== "HEALTHY" && health.status !== "DEGRADED") {
      throw new AdapterUnavailableError(`${this.metadata.slug}: scanner is ${health.status} — the scan stage degrades instead of inventing results (§86)`);
    }
    // §6/§13: targets come from the persisted scope snapshot ONLY.
    const scope = scopeRulesFromConfig(config);
    const cidrs = Array.isArray(config.scopeIncludeCidrs) ? (config.scopeIncludeCidrs as string[]) : [];
    const { targets, rejected } = generateScannerTargets({ ...scope, includeCidrs: cidrs });
    if (targets.length === 0) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: scope produced no scanner targets — nothing to scan`);
    }
    const logicalProfile = typeof config.logicalProfile === "string" ? config.logicalProfile : "BASELINE";
    const scanName = `dsrclone-${typeof config.scanId === "string" ? config.scanId : "scan"}`;
    const { scannerTaskId } = await this.connector.createScan(instance, { logicalProfile, targets, name: scanName });
    const sleep = this.poll.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
    const maxPolls = this.poll.maxPolls ?? 120;
    const intervalMs = this.poll.intervalMs ?? 5000;
    let status = "RUNNING";
    try {
      for (let i = 0; i < maxPolls; i++) {
        const s = await this.connector.getScanStatus(instance, scannerTaskId);
        status = s.status.toUpperCase();
        if (["DONE", "COMPLETED", "FINISHED", "COMPLETE"].includes(status)) break;
        if (["FAILED", "ERROR", "STOPPED", "CANCELLED", "ABORTED"].includes(status)) {
          throw new AdapterUnavailableError(`${this.metadata.slug}: scanner task ended ${status}`);
        }
        await sleep(intervalMs);
      }
      if (!["DONE", "COMPLETED", "FINISHED", "COMPLETE"].includes(status)) {
        await this.connector.cancel(instance, scannerTaskId).catch(() => undefined);
        throw new AdapterUnavailableError(`${this.metadata.slug}: scanner task did not complete within the polling budget — cancelled`);
      }
    } catch (err) {
      if (err instanceof AdapterUnavailableError) throw err;
      throw new AdapterUnavailableError(`${this.metadata.slug}: scanner task failed — ${err instanceof Error ? err.message : String(err)}`);
    }
    const report = await this.connector.fetchReport(instance, scannerTaskId);
    const envelope: ConnectorEnvelope & { checksum?: string } = {
      product: this.connector.product, slug: this.metadata.slug, instanceId: instance.id,
      contextId: scannerTaskId, sessionStatus: "NOT_APPLICABLE",
      findings: report.findings, endpoints: [], transactions: [], webSockets: [], observations: [],
      warnings: [...report.warnings, ...rejected.map((r) => `scope target rejected: ${r.value} (${r.reason})`)],
      metrics: { findingsImported: report.findings.length, targetsSubmitted: targets.length, scannerTask: 1 },
      checksum: report.checksum,
    };
    this.lastEnvelope = envelope;
    this.lastRaw = JSON.stringify(envelope);
    return { rawOutput: this.lastRaw };
  }

  async parse(raw: string): Promise<unknown> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedProxy();
    const envelope = JSON.parse(text) as ConnectorEnvelope;
    const parsed = emptyParsedProxy();
    parsed.findings = envelope.findings ?? [];
    parsed.warnings = envelope.warnings ?? [];
    parsed.metrics = envelope.metrics ?? {};
    parsed.records = parsed.findings.length;
    this.lastEnvelope = envelope;
    return parsed;
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedProxy;
    const hosts = new Set<string>();
    for (const f of p.findings ?? []) if (f.host) hosts.add(f.host);
    return {
      assets: [...hosts].map((host) => ({ host, type: "HOST", sources: [this.metadata.slug] })),
      services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [], artifacts: [],
      metrics: { ...(p.metrics ?? {}), parserWarnings: (p.warnings ?? []).length },
      mock: false,
    };
  }

  /** Remember plan-time config (mirrors the proxy adapters' pattern). */
  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

function vulnScannerMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "homepage" | "licenseType">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "NETWORK",
    executionMode: "EXTERNAL_API", riskLevel: "MODERATE",
    requiresApproval: true,
    supportedTargetTypes: ["IP_ADDRESS", "CIDR", "DOMAIN", "WEB_APPLICATION"],
    supportedOutputFormats: ["JSON", "XML"],
    capabilities: ["NETWORK_VULNERABILITY_ASSESSMENT", "VULNERABILITY_SCANNING", "SCAN_RESULT_IMPORT", "VULNERABILITY_DETECTION"],
    requiresCredentials: [],
    supportsContainerExecution: false,
    supportsCancellation: true,
    supportsProgress: true,
    defaultTimeoutSeconds: 3600, maxTimeoutSeconds: 7200,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 3600 },
    inputSchema: [
      ...CONNECTOR_INPUT_SCHEMA,
      { name: "scopeIncludeCidrs", type: "string[]", description: "Persisted scope CIDRs, supplied by the worker from the approved scope (§6)" },
      { name: "logicalProfile", type: "string", description: "Logical scan profile selected by policy (BASELINE/STANDARD/COMPREHENSIVE or NETWORK_*); resolved to an administrator-approved scanner policy id by the connector (§7/§12)" },
    ],
    ...partial,
  } as ToolMetadata;
}

export function greenboneMetadata(): ToolMetadata {
  return vulnScannerMeta({
    id: "greenbone-openvas", slug: "greenbone-openvas", name: "Greenbone / OpenVAS",
    description: "Open-source network vulnerability scanner via an administrator-managed Greenbone/OpenVAS deployment (Prompt 11 §3): ZeroSweep creates governed scan tasks over scope-derived targets with administrator-approved profiles and imports normalized results. Feed status is part of health (§5).",
    homepage: "https://www.greenbone.net", licenseType: "OPEN_SOURCE",
  });
}

export function nessusMetadata(): ToolMetadata {
  return vulnScannerMeta({
    id: "nessus-professional", slug: "nessus-professional", name: "Nessus Professional",
    description: "Commercial network vulnerability scanner (Prompt 11 §10) — COMMERCIAL / ADMIN_PROVIDED / LICENSE_REQUIRED: used only against an administrator-provided licensed Nessus environment, never redistributed. Unconfigured it reports NOT_CONFIGURED and never blocks the platform (§85).",
    homepage: "https://www.tenable.com/products/nessus", licenseType: "ADMIN_PROVIDED",
  });
}

/** Factory mirroring createProxyAdapters: connectors + worker adapters. */
export function createVulnScannerAdapters(deps: ConnectorDeps): VulnScannerAdapter[] {
  const greenbone = new GreenboneConnector(deps.transport, deps.endpoints, deps.secrets);
  const nessus = new NessusConnector(deps.transport, deps.endpoints, deps.secrets);
  return [
    new VulnScannerAdapter(greenbone, deps, greenboneMetadata()),
    new VulnScannerAdapter(nessus, deps, nessusMetadata()),
  ];
}

/** Structural check used by the worker's stage executor (§84 confinement). */
export function isVulnScannerAdapter(adapter: BaseSecurityToolAdapter): adapter is VulnScannerAdapter {
  return adapter instanceof VulnScannerAdapter;
}

/** Registration mirroring registerProxyAdapters (deployment-time,
 *  code-installed): worker/API inject Prisma-backed connector deps. */
export function registerVulnScannerAdapters(
  registry: { register(adapter: VulnScannerAdapter): void },
  deps: ConnectorDeps,
): VulnScannerAdapter[] {
  const adapters = createVulnScannerAdapters(deps);
  for (const adapter of adapters) registry.register(adapter as never);
  return adapters;
}
