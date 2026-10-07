import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { AdapterTarget, SecurityToolAdapter } from "../adapter/adapter.interface";
import type { AdapterInputField, ToolMetadata } from "../adapter/adapter.types";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedEndpoint, NormalizedHttpTransaction, NormalizedSecurityResult, NormalizedWebSocket } from "../findings/finding.types";
import type { ScopeRules } from "@dsrclone/validation";
import { TIMEOUT_FIELD, URLS_FIELD } from "../recon/recon-adapter.base";
import type { ParsedProxy } from "./parsers-proxy";
import type { ParsedObservation } from "../vuln/parsers-vuln";
import { BurpIssueParser, CaidoIssueParser, MitmproxyFlowParser, ZapIssueParser, emptyParsedProxy, toTransaction } from "./parsers-proxy";
import {
  BaseScannerConnector, assessSession, filterLogoutUrls,
  type ConnectorDeps,
} from "./connector";
import {
  PRODUCT_CAPABILITIES, PRODUCT_SLUGS, type ScannerContextRecord, type ScannerInstanceRecord,
  type ScannerProduct, type SessionProfileRecord,
} from "./types";
import type { NormalizedVulnFinding } from "../vuln/types";

/**
 * Product connectors (Prompt 8 §4/§9/§13) + their SecurityToolAdapter
 * wrappers. The connectors implement the interactive lifecycle against the
 * product's documented surface (ZAP API; Burp via the administrator-
 * provided bridge serving Burp's own XML issue export; Caido via its
 * GraphQL-style API, tolerated per installed version). The wrappers expose
 * the standard adapter lifecycle so orchestration, policy and the worker
 * treat connectors exactly like every other tool — with the difference
 * that execution is a bounded passive pipeline:
 *
 *   connect → createContext (scope from persisted rules) → configure
 *   authentication (reference only) → import endpoints/site map →
 *   passive analysis → import issues → assess session → cleanup (destroy
 *   context, always).
 *
 * Active scanning is NEVER part of this pipeline (§8/§38): the connectors
 * expose the gated startActiveScan() contract, and the pipeline does not
 * call it.
 */

export const INSTANCE_FIELD: AdapterInputField = { name: "instanceId", type: "string", description: "Registered scanner instance id, resolved by the worker from the workspace's admin-registered instances — never client-supplied (§16)" };
export const SESSION_PROFILE_FIELD: AdapterInputField = { name: "sessionProfileId", type: "string", description: "Session profile id bound to this scan (metadata + credential reference only, §18)" };
export const WORKSPACE_FIELD: AdapterInputField = { name: "workspaceId", type: "string", description: "Workspace id from trusted worker state (context isolation, §6)" };
export const ASSESSMENT_FIELD: AdapterInputField = { name: "assessmentId", type: "string", description: "Assessment id from trusted worker state (context binding, §6)" };
export const SCAN_FIELD: AdapterInputField = { name: "scanId", type: "string", description: "Scan id from trusted worker state" };
export const SCOPE_INCLUDE_FIELD: AdapterInputField = { name: "scopeIncludeHosts", type: "string[]", description: "Persisted scope include hosts, supplied by the worker from the approved scope (§6)" };
export const SCOPE_EXCLUDE_FIELD: AdapterInputField = { name: "scopeExcludeHosts", type: "string[]", description: "Persisted scope exclude hosts, supplied by the worker (§6)" };
export const SCOPE_PORTS_FIELD: AdapterInputField = { name: "scopeAllowedPorts", type: "number[]", description: "Persisted scope allowed ports, supplied by the worker (§6)" };
export const SCOPE_PATHS_FIELD: AdapterInputField = { name: "scopeAllowedPaths", type: "string[]", description: "Persisted scope allowed paths, supplied by the worker (§6)" };
export const SCOPE_EXCLUDED_PATHS_FIELD: AdapterInputField = { name: "scopeExcludedPaths", type: "string[]", description: "Persisted scope excluded paths, supplied by the worker (§6)" };

export const CONNECTOR_INPUT_SCHEMA: AdapterInputField[] = [
  INSTANCE_FIELD, SESSION_PROFILE_FIELD, WORKSPACE_FIELD, ASSESSMENT_FIELD, SCAN_FIELD,
  SCOPE_INCLUDE_FIELD, SCOPE_EXCLUDE_FIELD, SCOPE_PORTS_FIELD, SCOPE_PATHS_FIELD, SCOPE_EXCLUDED_PATHS_FIELD,
  URLS_FIELD, TIMEOUT_FIELD,
];

export function scopeRulesFromConfig(config: Record<string, unknown>): ScopeRules {
  const arr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  const nums = (v: unknown): number[] => (Array.isArray(v) ? v.filter((x): x is number => typeof x === "number") : []);
  return {
    includeHosts: arr(config.scopeIncludeHosts),
    excludeHosts: arr(config.scopeExcludeHosts),
    includeCidrs: [],
    allowedPorts: nums(config.scopeAllowedPorts),
    allowedPaths: arr(config.scopeAllowedPaths),
    excludedPaths: arr(config.scopeExcludedPaths),
  };
}

/** Serializable result of one passive pipeline run — the connector's raw
 *  output artifact (§26): normalized findings/endpoints/transactions with
 *  REDACTED display copies only. Raw traffic bytes never enter the
 *  envelope; they are hashed at parse time inside the parsers. */
export interface ConnectorEnvelope {
  product: ScannerProduct;
  slug: string;
  instanceId: string;
  contextId: string;
  sessionStatus: "NOT_APPLICABLE" | "VALID" | "EXPIRED" | "UNKNOWN";
  findings: NormalizedVulnFinding[];
  endpoints: NormalizedEndpoint[];
  transactions: NormalizedHttpTransaction[];
  webSockets: NormalizedWebSocket[];
  observations: ParsedObservation[];
  warnings: string[];
  metrics: Record<string, number>;
}

abstract class ProductConnector extends BaseScannerConnector {
  /** Run the full bounded passive pipeline and assemble the envelope. */
  async collectPassiveResults(contextId: string, sessionProfile?: SessionProfileRecord): Promise<ConnectorEnvelope> {
    const context = this.contextById(contextId);
    const imported = await this.importEndpoints(contextId);
    await this.startPassiveAnalysis(contextId);
    const issues = await this.getIssues(contextId);
    const extras = this.drainExportExtras();
    const endpoints = [...imported.endpoints, ...extras.endpoints];
    const transactions = [...imported.transactions, ...extras.transactions];
    const sessionStatus = assessSession(sessionProfile, transactions);
    return {
      product: this.product,
      slug: this.slug,
      instanceId: context.instanceId,
      contextId,
      sessionStatus,
      findings: issues,
      endpoints,
      transactions: transactions.slice(0, this.budget.maxPassiveTransactions),
      webSockets: [...imported.webSockets, ...extras.webSockets],
      observations: extras.observations,
      warnings: extras.warnings,
      metrics: {
        endpointsImported: endpoints.length,
        transactionsAnalyzed: transactions.length,
        passiveIssues: issues.length,
        sessionExpired: sessionStatus === "EXPIRED" ? 1 : 0,
        contextsCreated: 1,
      },
    };
  }

  /** Products whose issue export also carries traffic/inventory (Burp XML,
   *  Caido) stash it during getIssues/import; drained once per run. */
  protected drainExportExtras(): { endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[]; observations: ParsedObservation[]; warnings: string[] } {
    return { endpoints: [], transactions: [], webSockets: [], observations: [], warnings: [] };
  }

  protected instanceFor(context: ScannerContextRecord): Promise<ScannerInstanceRecord> {
    return this.deps.instances.getById(context.instanceId).then((i) => {
      if (!i) throw new AdapterUnavailableError(`${this.slug}: scanner instance ${context.instanceId} no longer exists`);
      return i;
    });
  }
}

// ------------------------------- ZAP (§4–§8) -------------------------------

const zapRegexEscape = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export class ZapConnector extends ProductConnector {
  readonly product = "ZAP" as const;
  constructor(deps: ConnectorDeps) { super(deps); }
  private readonly parser = new ZapIssueParser();
  private lastParsed: ParsedProxy = emptyParsedProxy();

  protected async probe(instance: ScannerInstanceRecord, baseUrl: string, approvedInternal?: boolean) {
    void baseUrl; void approvedInternal;
    const res = await this.call(instance, { method: "GET", path: "/JSON/core/view/version/" }, "X-ZAP-API-Key");
    if (res.status !== 200) throw new Error(`ZAP version probe returned HTTP ${res.status}`);
    const parsed = JSON.parse(res.body) as { version?: string };
    return { version: parsed.version, latencyMs: res.latencyMs };
  }

  protected override async vendorCreateContext(context: ScannerContextRecord, instance: ScannerInstanceRecord): Promise<void> {
    // ZAP management API is reached ONLY through this trusted connector —
    // it is never exposed to users (§5).
    await this.call(instance, { method: "GET", path: "/JSON/context/action/newContext/", query: { contextName: context.vendorContextName } }, "X-ZAP-API-Key");
  }

  protected override async vendorConfigureScope(context: ScannerContextRecord, instance: ScannerInstanceRecord, _scope: ScopeRules): Promise<void> {
    for (const target of context.includedTargets) {
      const host = new URL(target).hostname;
      await this.call(instance, {
        method: "GET", path: "/JSON/context/action/includeInContext/",
        query: { contextName: context.vendorContextName, regex: `https?://${zapRegexEscape(host)}.*` },
      }, "X-ZAP-API-Key");
    }
    for (const host of context.excludedTargets) {
      await this.call(instance, {
        method: "GET", path: "/JSON/context/action/excludeFromContext/",
        query: { contextName: context.vendorContextName, regex: `https?://${zapRegexEscape(host.replace(/^\*\./, ""))}.*` },
      }, "X-ZAP-API-Key");
    }
  }

  protected override async vendorDestroyContext(context: ScannerContextRecord, instance: ScannerInstanceRecord): Promise<void> {
    await this.call(instance, { method: "GET", path: "/JSON/context/action/removeContext/", query: { contextName: context.vendorContextName } }, "X-ZAP-API-Key");
  }

  async importEndpoints(contextId: string): Promise<{ endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[] }> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const endpoints: NormalizedEndpoint[] = [];
    const urlsRes = await this.call(instance, { method: "GET", path: "/JSON/core/view/urls/", query: { contextName: context.vendorContextName } }, "X-ZAP-API-Key");
    const urls = JSON.parse(urlsRes.body) as Array<{ url?: string } | string>;
    for (const entry of urls.slice(0, this.budget.maxImportedEndpoints)) {
      const url = typeof entry === "string" ? entry : entry.url;
      if (!url) continue;
      endpoints.push({ url, method: "GET", parameterNames: [], source: this.slug, sources: [this.slug] });
    }
    // Traffic (§25): bounded message harvest. Messages are the passive
    // record of what the proxy observed — imported, never replayed.
    const transactions: NormalizedHttpTransaction[] = [];
    const listRes = await this.call(instance, {
      method: "GET", path: "/JSON/core/view/messages/",
      query: { contextName: context.vendorContextName, start: "0", count: String(Math.min(100, this.budget.maxPassiveTransactions)) },
    }, "X-ZAP-API-Key");
    const ids = (JSON.parse(listRes.body) as Array<{ id?: string | number }>).map((x) => String(x.id)).filter(Boolean);
    for (const id of ids) {
      const msgRes = await this.call(instance, { method: "GET", path: "/JSON/core/view/message/", query: { id } }, "X-ZAP-API-Key");
      const msg = JSON.parse(msgRes.body) as { requestHeader?: string; requestBody?: string; responseHeader?: string; responseBody?: string };
      const tx = zapMessageToTransaction(msg, this.slug);
      if (tx) transactions.push(tx);
    }
    return { endpoints, transactions, webSockets: [] };
  }

  async startPassiveAnalysis(contextId: string): Promise<void> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    // Safe crawl of the already-scoped context (§4/§7): the spider is
    // constrained to the context (whose includes were scope-checked at
    // creation) and logout URLs are never queued (§47).
    const { kept } = filterLogoutUrls(context.includedTargets);
    for (const target of kept) {
      await this.call(instance, { method: "GET", path: "/JSON/spider/action/scan/", query: { url: target, contextName: context.vendorContextName } }, "X-ZAP-API-Key");
    }
    for (let i = 0; i < 30; i++) {
      const status = await this.call(instance, { method: "GET", path: "/JSON/spider/view/status/", query: { scanId: "0" } }, "X-ZAP-API-Key");
      const parsed = JSON.parse(status.body) as { status?: string };
      if (parsed.status === "100") break;
    }
    // Passive analysis completes when the pscan queue drains (bounded).
    for (let i = 0; i < 30; i++) {
      const res = await this.call(instance, { method: "GET", path: "/JSON/pscan/view/recordsToScan/" }, "X-ZAP-API-Key");
      const parsed = JSON.parse(res.body) as { recordsToScan?: string };
      if (!parsed.recordsToScan || parsed.recordsToScan === "0") break;
    }
  }

  async getProgress(contextId: string): Promise<{ phase: string; percent: number; detail?: string }> {
    this.contextById(contextId);
    return { phase: "PASSIVE_ANALYSIS", percent: 100, detail: "Passive records processed" };
  }

  async getIssues(contextId: string): Promise<NormalizedVulnFinding[]> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const base = context.includedTargets[0] ?? "";
    const res = await this.call(instance, {
      method: "GET", path: "/JSON/core/view/alerts/",
      query: { baseurl: base, start: "0", count: String(this.budget.maxImportedIssues) },
    }, "X-ZAP-API-Key");
    const parsed = this.parser.parse(JSON.parse(res.body));
    this.lastParsed = parsed;
    return parsed.findings;
  }

  protected override drainExportExtras() {
    const p = this.lastParsed;
    this.lastParsed = emptyParsedProxy();
    return { endpoints: [], transactions: [], webSockets: [], observations: p.observations, warnings: p.warnings };
  }

  async exportArtifacts(contextId: string): Promise<{ artifactKind: string; reference: string }[]> {
    this.contextById(contextId);
    return [{ artifactKind: "ZAP_ALERTS", reference: `scanner-context:${contextId}/alerts` }];
  }
}

/** ZAP message → normalized transaction: raw header/body pairs are
 *  assembled and handed to the redaction pipeline (toTransaction). */
export function zapMessageToTransaction(
  msg: { requestHeader?: string; requestBody?: string; responseHeader?: string; responseBody?: string },
  source: string,
): NormalizedHttpTransaction | null {
  const reqHeader = msg.requestHeader ?? "";
  const firstLine = reqHeader.split(/\r?\n/)[0] ?? "";
  const [method = "GET", rawTarget = "/"] = firstLine.split(/\s+/);
  let url = rawTarget;
  if (!/^https?:\/\//i.test(rawTarget)) {
    const hostMatch = reqHeader.match(/^host:\s*(.+)$/im);
    const host = hostMatch?.[1]?.trim() ?? "";
    if (!host) return null;
    url = `https://${host}${rawTarget.startsWith("/") ? rawTarget : `/${rawTarget}`}`;
  }
  const resHeader = msg.responseHeader ?? "";
  const status = Number((resHeader.split(/\r?\n/)[0] ?? "").split(/\s+/)[1]) || undefined;
  const joinRaw = (header: string, body?: string): string =>
    `${header.replace(/\r?\n?$/, "")}\r\n\r\n${body ?? ""}`;
  return toTransaction({
    method, url, ...(status !== undefined ? { statusCode: status } : {}),
    requestRaw: joinRaw(reqHeader, msg.requestBody),
    responseRaw: resHeader ? joinRaw(resHeader, msg.responseBody) : undefined,
    source,
  });
}

// ------------------------------- Burp (§9–§12) -------------------------------

export class BurpConnector extends ProductConnector {
  readonly product = "BURP" as const;
  constructor(deps: ConnectorDeps) { super(deps); }
  private readonly parser = new BurpIssueParser();
  private lastExport: ParsedProxy = emptyParsedProxy();

  protected async probe(instance: ScannerInstanceRecord, _baseUrl: string, _approvedInternal?: boolean) {
    // Burp is administrator-provided (§9): DSRclone never assumes an API.
    // The probe talks to the DSRclone Burp bridge the administrator runs
    // inside the licensed environment (documented in docs/tools/proxy/
    // burp.md) — if it does not answer, the connector is UNAVAILABLE,
    // never "probably fine" (§66).
    const res = await this.call(instance, { method: "GET", path: "/dsrclone/health" }, "X-DSRclone-Bridge-Key");
    if (res.status !== 200) throw new Error(`Burp bridge health returned HTTP ${res.status}`);
    const parsed = JSON.parse(res.body) as { version?: string; licenseState?: string };
    return { version: parsed.version, licenseState: parsed.licenseState, latencyMs: res.latencyMs };
  }

  async importEndpoints(contextId: string): Promise<{ endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[] }> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const res = await this.call(instance, { method: "GET", path: "/dsrclone/site-map" }, "X-DSRclone-Bridge-Key");
    const entries = JSON.parse(res.body) as Array<{ url?: string; method?: string; statusCode?: number }>;
    const endpoints: NormalizedEndpoint[] = [];
    for (const e of entries.slice(0, this.budget.maxImportedEndpoints)) {
      if (!e.url) continue;
      endpoints.push({ url: e.url, method: e.method ?? "GET", ...(e.statusCode !== undefined ? { statusCode: e.statusCode } : {}), parameterNames: [], source: this.slug, sources: [this.slug] });
    }
    return { endpoints, transactions: [], webSockets: [] };
  }

  async startPassiveAnalysis(_contextId: string): Promise<void> {
    // Burp's passive analysis runs continuously inside the administrator's
    // Burp instance over proxied traffic; there is nothing for DSRclone to
    // start — and DSRclone never drives Burp interactively beyond the
    // documented bridge contract (§10/§11).
  }

  async getProgress(contextId: string): Promise<{ phase: string; percent: number; detail?: string }> {
    this.contextById(contextId);
    return { phase: "PASSIVE_ANALYSIS", percent: 100, detail: "Burp passive issues are collected continuously by the licensed instance; import reflects the current site map" };
  }

  async getIssues(contextId: string): Promise<NormalizedVulnFinding[]> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const res = await this.call(instance, { method: "GET", path: "/dsrclone/issues-export" }, "X-DSRclone-Bridge-Key");
    if (res.status !== 200) throw new AdapterUnavailableError(`burp-suite-professional: issues export returned HTTP ${res.status}`);
    const parsed = this.parser.parse(res.body);
    this.lastExport = parsed;
    return parsed.findings;
  }

  protected override drainExportExtras() {
    const p = this.lastExport;
    this.lastExport = emptyParsedProxy();
    return { endpoints: p.endpoints, transactions: p.transactions, webSockets: [], observations: p.observations, warnings: p.warnings };
  }

  async exportArtifacts(contextId: string): Promise<{ artifactKind: string; reference: string }[]> {
    this.contextById(contextId);
    return [{ artifactKind: "BURP_ISSUES_XML", reference: `scanner-context:${contextId}/issues-export` }];
  }
}

// ------------------------------- Caido (§13) -------------------------------

export class CaidoConnector extends ProductConnector {
  readonly product = "CAIDO" as const;
  constructor(deps: ConnectorDeps) { super(deps); }
  private readonly parser = new CaidoIssueParser();
  private importParsed: ParsedProxy = emptyParsedProxy();

  private async graphql(instance: ScannerInstanceRecord, query: string): Promise<unknown> {
    const res = await this.call(instance, {
      method: "POST", path: "/graphql",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ query }),
    }, "Authorization");
    if (res.status !== 200) throw new Error(`Caido GraphQL returned HTTP ${res.status}`);
    return JSON.parse(res.body) as unknown;
  }

  protected async probe(instance: ScannerInstanceRecord, _baseUrl: string, _approvedInternal?: boolean) {
    const body = await this.graphql(instance, "{ __typename }");
    const ok = body !== null && typeof body === "object";
    if (!ok) throw new Error("Caido GraphQL probe returned an unexpected payload");
    // §13: capabilities/version vary per installed Caido — reachability
    // is reported as DEGRADED (version unconfirmed) by the base health
    // logic, never upgraded on assumption.
    return { latencyMs: 0 };
  }

  async importEndpoints(contextId: string): Promise<{ endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[] }> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const payload = await this.graphql(instance, "{ requests { method url host path status request response createdAt } }");
    const parsed = this.parser.parse(payload);
    this.importParsed = parsed;
    return { endpoints: parsed.endpoints, transactions: parsed.transactions, webSockets: parsed.webSockets };
  }

  async startPassiveAnalysis(_contextId: string): Promise<void> {
    // Caido analyzes traffic passively as it is proxied (§13); the
    // connector imports what was observed — it does not generate traffic.
  }

  async getProgress(contextId: string): Promise<{ phase: string; percent: number; detail?: string }> {
    this.contextById(contextId);
    return { phase: "TRAFFIC_ANALYSIS", percent: 100 };
  }

  async getIssues(contextId: string): Promise<NormalizedVulnFinding[]> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const payload = await this.graphql(instance, "{ findings { id title description severity url } }");
    const parsed = this.parser.parse(payload);
    return parsed.findings;
  }

  protected override drainExportExtras() {
    const p = this.importParsed;
    this.importParsed = emptyParsedProxy();
    return { endpoints: [], transactions: [], webSockets: [], observations: p.observations, warnings: p.warnings };
  }

  async exportArtifacts(contextId: string): Promise<{ artifactKind: string; reference: string }[]> {
    this.contextById(contextId);
    return [{ artifactKind: "CAIDO_EXPORT", reference: `scanner-context:${contextId}/export` }];
  }
}

// ------------------------------- Adapter wrappers -------------------------------

function connectorMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "executionMode" | "licenseType" | "riskLevel" | "requiresApproval">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "WEB",
    supportedTargetTypes: ["WEB_APPLICATION", "API"],
    supportedOutputFormats: ["JSON", "XML"],
    capabilities: [],
    requiresCredentials: [],
    supportsContainerExecution: false,
    supportsCancellation: true,
    supportsProgress: true,
    defaultTimeoutSeconds: 1200,
    maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 1200 },
    inputSchema: CONNECTOR_INPUT_SCHEMA,
    ...partial,
  } as ToolMetadata;
}

/**
 * SecurityToolAdapter wrapper for an interactive connector. Execution IS
 * the passive pipeline (connect → context → import → passive analysis →
 * issues → cleanup); there is no command, no container and no arbitrary
 * request surface. Availability = a healthy configured instance exists
 * (§53/§66): with none, the adapter reports unavailable and the worker's
 * policy gate denies with TOOL_UNAVAILABLE — the stage degrades honestly
 * instead of pretending a scanner ran.
 */
export class ScannerConnectorAdapter extends BaseSecurityToolAdapter {
  readonly metadata: ToolMetadata;
  private lastEnvelope: ConnectorEnvelope | undefined;
  private lastRaw = "";

  constructor(readonly connector: ProductConnector, metadata: ToolMetadata) {
    super();
    this.metadata = metadata;
  }

  async checkAvailability(): Promise<boolean> {
    return this.connector.checkAvailability();
  }

  override async healthCheck(): Promise<{ status: string; detail?: string }> {
    const health = await this.connector.healthCheck();
    return {
      status: health.status,
      detail: [health.detail, health.version ? `version ${health.version}` : undefined, health.licenseState ? `license: ${health.licenseState}` : undefined]
        .filter(Boolean).join(" — "),
    };
  }

  async buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    void target;
    return {
      adapterId: this.metadata.id,
      toolId: this.metadata.id,
      executionMode: this.metadata.executionMode,
      arguments: [],
      environmentReferences: [],
      timeoutSeconds: Math.min(typeof config.timeoutSeconds === "number" ? config.timeoutSeconds : this.metadata.defaultTimeoutSeconds, this.metadata.maxTimeoutSeconds),
      cpuLimit: this.metadata.resources.cpu,
      memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST",
      expectedOutputFormat: "JSON",
      outputFiles: [],
    };
  }

  async execute(plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    void plan;
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError(`${this.metadata.slug}: execute() called without buildExecutionPlan()`);
    const instanceId = typeof config.instanceId === "string" ? config.instanceId : undefined;
    if (!instanceId) {
      throw new AdapterUnavailableError(`${this.metadata.slug}: no scanner instance is configured for this workspace — connector reports NOT_CONFIGURED (§66)`);
    }
    const workspaceId = typeof config.workspaceId === "string" ? config.workspaceId : "";
    const assessmentId = typeof config.assessmentId === "string" ? config.assessmentId : "";
    const scanId = typeof config.scanId === "string" ? config.scanId : undefined;
    const scopeRules = scopeRulesFromConfig(config);
    const urls = Array.isArray(config.urls) ? (config.urls as string[]) : [];
    const targetBase = this.pendingTarget ? [this.pendingTarget.value.includes("://") ? this.pendingTarget.value : `https://${this.pendingTarget.host}/`] : [];
    const baseUrls = [...new Set([...targetBase, ...urls])].slice(0, 25);
    const sessionProfile = await this.resolveSessionProfile(config);

    await this.connector.connect(instanceId);
    const context = await this.connector.createContext({
      instanceId, workspaceId, assessmentId, ...(scanId ? { scanId } : {}),
      scopeRules, targetBaseUrls: baseUrls, ...(sessionProfile ? { sessionProfile } : {}),
    });
    try {
      await this.connector.configureScope(context.id, scopeRules, baseUrls);
      if (sessionProfile) await this.connector.configureAuthentication(context.id, sessionProfile);
      const envelope = await this.connector.collectPassiveResults(context.id, sessionProfile);
      this.lastEnvelope = envelope;
      this.lastRaw = JSON.stringify(envelope);
      return { rawOutput: this.lastRaw };
    } finally {
      // §6: contexts are destroyed after every run — authenticated
      // sessions are never left behind or reused across assessments.
      await this.connector.cleanup(context.id).catch(() => undefined);
      await this.connector.disconnect().catch(() => undefined);
    }
  }

  private pendingConfig: Record<string, unknown> | undefined;
  private pendingTarget: AdapterTarget | undefined;

  private async resolveSessionProfile(config: Record<string, unknown>): Promise<SessionProfileRecord | undefined> {
    const id = typeof config.sessionProfileId === "string" ? config.sessionProfileId : undefined;
    if (!id) return undefined;
    const provider = this.connector.sessionProfiles;
    return provider ? (await provider.getById(id)) ?? undefined : undefined;
  }

  async parse(raw: string): Promise<unknown> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedProxy();
    const envelope = JSON.parse(text) as ConnectorEnvelope;
    const parsed = emptyParsedProxy();
    parsed.findings = envelope.findings ?? [];
    parsed.endpoints = envelope.endpoints ?? [];
    parsed.transactions = envelope.transactions ?? [];
    parsed.webSockets = envelope.webSockets ?? [];
    parsed.observations = envelope.observations ?? [];
    parsed.warnings = envelope.warnings ?? [];
    parsed.metrics = envelope.metrics ?? {};
    parsed.records = parsed.findings.length + parsed.endpoints.length + parsed.transactions.length;
    this.lastEnvelope = envelope;
    return parsed;
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedProxy;
    const envelope = this.lastEnvelope;
    // Hosts the connector actually observed (endpoints / transactions /
    // websockets) become asset records so the worker can attach endpoints
    // and transactions to them — provenance is the connector itself, and
    // scope verdicts are assigned during result processing (§30).
    const hosts = new Set<string>();
    for (const e of p.endpoints ?? []) { try { hosts.add(new URL(e.url).hostname); } catch { /* skip */ } }
    for (const t of p.transactions ?? []) hosts.add(t.host);
    for (const w of p.webSockets ?? []) { try { hosts.add(new URL(w.url).hostname); } catch { /* skip */ } }
    return {
      assets: [...hosts].filter(Boolean).map((host) => ({ host, type: "HOST", sources: [this.metadata.slug] })),
      services: [],
      endpoints: p.endpoints ?? [],
      technologies: [],
      findings: p.findings ?? [],
      ...(p.transactions && p.transactions.length > 0 ? { transactions: p.transactions } : {}),
      ...(p.webSockets && p.webSockets.length > 0 ? { webSockets: p.webSockets } : {}),
      artifacts: [],
      metrics: {
        ...(p.metrics ?? {}),
        ...(envelope ? {
          endpointsImported: envelope.metrics.endpointsImported ?? p.endpoints.length,
          transactionsAnalyzed: envelope.metrics.transactionsAnalyzed ?? (p.transactions ?? []).length,
          passiveIssues: envelope.metrics.passiveIssues ?? p.findings.length,
          sessionExpired: envelope.sessionStatus === "EXPIRED" ? 1 : 0,
          contextsCreated: 1,
          observations: (p.observations ?? []).length,
          parserWarnings: (p.warnings ?? []).length,
        } : {}),
      },
      mock: false,
    };
  }

  /** buildExecutionPlan records the run configuration (the executor's
   *  trusted, worker-assembled config) for execute(), mirroring the
   *  Nuclei adapter's lastConfig pattern. */
  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    await this.connector.validateConfiguration(config);
  }
}

/** Adapter factory: wraps a connector and remembers plan-time state. */
export function wrapConnector(connector: ProductConnector, metadata: ToolMetadata): ScannerConnectorAdapter {
  const adapter = new ScannerConnectorAdapter(connector, metadata);
  const originalBuild = adapter.buildExecutionPlan.bind(adapter);
  adapter.buildExecutionPlan = async (target: AdapterTarget, config: Record<string, unknown>) => {
    (adapter as unknown as { pendingConfig: Record<string, unknown> }).pendingConfig = config;
    (adapter as unknown as { pendingTarget: AdapterTarget }).pendingTarget = target;
    return originalBuild(target, config);
  };
  return adapter;
}

export function zapMetadata(): ToolMetadata {
  return connectorMeta({
    id: "owasp-zap", slug: "owasp-zap", name: "OWASP ZAP",
    description: "Open-source web proxy/scanner via its daemon API — passive analysis, context management, endpoint + issue import through the trusted connector (Prompt 8 §4). Active scanning capability exists in metadata only: INTRUSIVE, approval-gated, disabled by default (§8).",
    homepage: "https://www.zaproxy.org",
    executionMode: "EXTERNAL_API", licenseType: "OPEN_SOURCE", riskLevel: "MODERATE", requiresApproval: false,
    // PIPELINE capabilities (§37): what this adapter offers the
    // orchestration engine. The product ceiling (PRODUCT_CAPABILITIES)
    // also lists WEB_CRAWLING / VULNERABILITY_SCANNING / ENDPOINT_
    // DISCOVERY — ZAP's spider and alert engine run INSIDE the passive
    // pipeline, never as standalone crawl/vuln stages, so those are
    // deliberately not pipeline capabilities: the connector executes
    // only in PASSIVE_SECURITY_ANALYSIS.
    capabilities: ["PROXY", "PASSIVE_ANALYSIS", "CONTEXT_MANAGEMENT", "ENDPOINT_IMPORT", "ISSUE_IMPORT", "ACTIVE_WEB_SCANNING"],
  });
}

export function burpMetadata(): ToolMetadata {
  return connectorMeta({
    id: "burp-suite-professional", slug: "burp-suite-professional", name: "Burp Suite Professional",
    description: "Commercial web proxy/scanner — ADMIN_PROVIDED licensed environment (DSRclone never redistributes Burp, §9). Passive site-map + issue import through the administrator's bridge; active scanning INTRUSIVE and approval-gated (§12). Unconfigured deployments report NOT_CONFIGURED (§66).",
    homepage: "https://portswigger.net/burp",
    executionMode: "ADMIN_PROVIDED", licenseType: "ADMIN_PROVIDED", riskLevel: "MODERATE", requiresApproval: true,
    // Pipeline capabilities only (see zapMetadata): Burp's crawl/scan
    // engines stay inside the administrator's licensed instance; the
    // connector's pipeline surface is passive import.
    capabilities: ["PROXY", "PASSIVE_ANALYSIS", "SITE_MAP_IMPORT", "ISSUE_IMPORT", "ACTIVE_WEB_SCANNING"],
  });
}

export function caidoMetadata(): ToolMetadata {
  return connectorMeta({
    id: "caido", slug: "caido", name: "Caido",
    description: "Modern web security proxy — traffic analysis, endpoint/request collection and issue import where the installed Caido version supports it (Prompt 8 §13). Capabilities are detected per deployment, never assumed (§14).",
    homepage: "https://caido.io",
    executionMode: "EXTERNAL_API", licenseType: "OPEN_SOURCE", riskLevel: "MODERATE", requiresApproval: false,
    capabilities: [...PRODUCT_CAPABILITIES.CAIDO],
  });
}

// ------------------------------- mitmproxy (Prompt 9 §33) -------------------------------

/**
 * mitmproxy connector (§33): an import/traffic-intelligence connector
 * over an administrator-run mitmweb instance. It reads the flow list
 * through the SSRF-guarded transport, normalizes flows into
 * transactions/API endpoints/WebSocket inventory, and returns NO issues
 * — mitmproxy is an observation source, not a vulnerability scanner.
 * The platform never proxies customer traffic itself in this phase and
 * never replays captured flows (§34: sensitive values are redacted at
 * parse; authorization material is visible as presence only).
 */
export class MitmproxyConnector extends ProductConnector {
  readonly product = "MITMPROXY" as const;
  constructor(deps: ConnectorDeps) { super(deps); }
  private readonly parser = new MitmproxyFlowParser();
  private importParsed: ParsedProxy = emptyParsedProxy();

  protected async probe(instance: ScannerInstanceRecord, _baseUrl: string, _approvedInternal?: boolean) {
    const res = await this.call(instance, { method: "GET", path: "/flows" }, "Authorization");
    if (res.status !== 200) throw new Error(`mitmweb flow probe returned HTTP ${res.status}`);
    const flows = JSON.parse(res.body) as unknown;
    if (!Array.isArray(flows)) throw new Error("mitmweb /flows returned an unexpected payload");
    // mitmweb does not expose a version on the flow API — reachability
    // is reported DEGRADED (version unconfirmed) by the base health
    // logic, never upgraded on assumption (same posture as Caido, §13).
    return { latencyMs: res.latencyMs };
  }

  async importEndpoints(contextId: string): Promise<{ endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[] }> {
    const context = this.contextById(contextId);
    const instance = await this.instanceFor(context);
    const res = await this.call(instance, { method: "GET", path: "/flows" }, "Authorization");
    if (res.status !== 200) throw new Error(`mitmweb /flows returned HTTP ${res.status}`);
    const parsed = this.parser.parse(JSON.parse(res.body) as unknown, this.slug);
    this.importParsed = parsed;
    return { endpoints: parsed.endpoints, transactions: parsed.transactions, webSockets: parsed.webSockets };
  }

  async startPassiveAnalysis(_contextId: string): Promise<void> {
    // mitmproxy observes traffic as it flows (§33); analysis here is the
    // import itself. The connector generates no traffic of its own.
  }

  async getProgress(contextId: string): Promise<{ phase: string; percent: number; detail?: string }> {
    this.contextById(contextId);
    return { phase: "TRAFFIC_ANALYSIS", percent: 100 };
  }

  async getIssues(_contextId: string): Promise<NormalizedVulnFinding[]> {
    // §33: traffic intelligence only — mitmproxy observations never
    // become vulnerability findings.
    return [];
  }

  protected override drainExportExtras() {
    const p = this.importParsed;
    this.importParsed = emptyParsedProxy();
    return { endpoints: [], transactions: [], webSockets: [], observations: p.observations, warnings: p.warnings };
  }

  async exportArtifacts(contextId: string): Promise<{ artifactKind: string; reference: string }[]> {
    this.contextById(contextId);
    return [{ artifactKind: "MITMPROXY_FLOWS", reference: `scanner-context:${contextId}/flows` }];
  }
}

export function mitmproxyMetadata(): ToolMetadata {
  return connectorMeta({
    id: "mitmproxy", slug: "mitmproxy", name: "mitmproxy",
    description: "Open-source interactive proxy — API traffic capture, endpoint discovery from observed flows, and WebSocket inventory (Prompt 9 §33). Traffic intelligence only: no vulnerability findings are derived from mitmproxy.",
    homepage: "https://mitmproxy.org",
    executionMode: "EXTERNAL_API", licenseType: "OPEN_SOURCE", riskLevel: "MODERATE", requiresApproval: false,
    capabilities: [...PRODUCT_CAPABILITIES.MITMPROXY],
  });
}

export function createProxyConnectors(deps: ConnectorDeps): { zap: ZapConnector; burp: BurpConnector; caido: CaidoConnector; mitmproxy: MitmproxyConnector } {
  return { zap: new ZapConnector(deps), burp: new BurpConnector(deps), caido: new CaidoConnector(deps), mitmproxy: new MitmproxyConnector(deps) };
}

export function createProxyAdapters(deps: ConnectorDeps): ScannerConnectorAdapter[] {
  const { zap, burp, caido, mitmproxy } = createProxyConnectors(deps);
  return [
    wrapConnector(zap, zapMetadata()),
    wrapConnector(burp, burpMetadata()),
    wrapConnector(caido, caidoMetadata()),
    wrapConnector(mitmproxy, mitmproxyMetadata()),
  ];
}

/** Structural check used by the worker to emit scanner lifecycle events. */
export function isScannerConnectorAdapter(adapter: SecurityToolAdapter): adapter is ScannerConnectorAdapter {
  return adapter instanceof ScannerConnectorAdapter;
}

export { PRODUCT_SLUGS };
