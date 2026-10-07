import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import { blockedTargetReason } from "../scope/scope.matcher";
import { ScopeMatcher } from "../scope/scope.matcher";
import type { ScopeRules } from "@dsrclone/validation";
import type { Capability } from "../adapter/adapter.types";
import type { NormalizedEndpoint, NormalizedHttpTransaction, NormalizedWebSocket } from "../findings/finding.types";
import type { NormalizedVulnFinding } from "../vuln/types";
import { evaluateActiveScanGate, type ActiveScanGateDecision, type ActiveScanGateInput } from "./approval";
import { clampProxyBudget, type ProxyBudget } from "./budget";
import { isLogoutUrl } from "./classify";
import type { ParsedProxy } from "./parsers-proxy";
import { emptyParsedProxy } from "./parsers-proxy";
import {
  PRODUCT_CAPABILITIES, PRODUCT_SLUGS, type EndpointResolver, type ScannerContextRecord,
  type ScannerHealth, type ScannerInstanceProvider, type ScannerInstanceRecord,
  type ScannerProduct, type SecretResolver, type SessionProfileProvider, type SessionProfileRecord,
} from "./types";

/**
 * InteractiveScannerConnector (Prompt 8 §2–§3). Proxy/scanner products are
 * services with contexts, sessions and state — this contract models that
 * lifecycle directly instead of forcing them into a CLI shape, while the
 * adapter classes (adapters-proxy.ts) still expose the standard
 * SecurityToolAdapter lifecycle to the orchestration engine.
 *
 * Every method is bounded by the platform: contexts are created per
 * assessment with scope configured FROM the persisted scope (never from
 * connector-side input), secrets are resolved per call from references,
 * and active scanning exists only behind evaluateActiveScanGate (§8/§12).
 */
export interface InteractiveScannerConnector {
  readonly product: ScannerProduct;
  readonly slug: string;
  checkAvailability(): Promise<boolean>;
  healthCheck(instanceId?: string): Promise<ScannerHealth>;
  connect(instanceId: string): Promise<void>;
  disconnect(): Promise<void>;
  validateConfiguration(config: Record<string, unknown>): Promise<void>;
  createContext(input: {
    instanceId: string; workspaceId: string; assessmentId: string; scanId?: string;
    scopeRules: ScopeRules; targetBaseUrls: string[]; sessionProfile?: SessionProfileRecord;
  }): Promise<ScannerContextRecord>;
  configureScope(contextId: string, scopeRules: ScopeRules, targetBaseUrls: string[]): Promise<void>;
  configureAuthentication(contextId: string, sessionProfile?: SessionProfileRecord): Promise<void>;
  importEndpoints(contextId: string): Promise<{ endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[] }>;
  startPassiveAnalysis(contextId: string): Promise<void>;
  getProgress(contextId: string): Promise<{ phase: string; percent: number; detail?: string }>;
  getIssues(contextId: string): Promise<NormalizedVulnFinding[]>;
  exportArtifacts(contextId: string): Promise<{ artifactKind: string; reference: string }[]>;
  startActiveScan(contextId: string, gate: ActiveScanGateInput): Promise<{ started: boolean; decision: ActiveScanGateDecision }>;
  cancel(contextId: string): Promise<void>;
  cleanup(contextId: string): Promise<void>;
}

// ------------------------------- Transport -------------------------------

export interface ConnectorTransportRequest {
  method: "GET" | "POST";
  path: string;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: string;
}

export interface ConnectorTransportResponse {
  status: number;
  body: string;
  latencyMs: number;
}

/**
 * The ONLY channel through which connectors talk to scanner deployments.
 * The endpoint comes from the trusted EndpointResolver (admin server
 * configuration), never from request data (§17); the secret (when the
 * instance declares a credential reference) is attached by the connector
 * as a header for this call only and never logged (§20).
 */
export interface ScannerTransport {
  request(input: {
    baseUrl: string;
    approvedInternal?: boolean;
    request: ConnectorTransportRequest;
  }): Promise<ConnectorTransportResponse>;
}

/** Hosts that must NEVER be reached via a scanner endpoint, even for
 *  approved internal deployments (§71): loopback, link-local/metadata and
 *  unspecified ranges are platform infrastructure, full stop. */
function hardBlockedReason(host: string): string | null {
  const h = host.toLowerCase().replace(/^\[|\]$/g, ""); // URL.hostname keeps IPv6 brackets
  if (h === "localhost" || h.endsWith(".localhost")) return "localhost is never a scanner endpoint";
  if (h === "metadata.google.internal") return "cloud metadata host is never a scanner endpoint";
  if (h === "::1") return "IPv6 loopback is never a scanner endpoint";
  if (/^127\./.test(h)) return "loopback range is never a scanner endpoint";
  if (/^169\.254\./.test(h) || /^fe[89ab][0-9a-f]:/.test(h)) return "link-local / metadata range is never a scanner endpoint";
  if (/^0\./.test(h)) return "unspecified range is never a scanner endpoint";
  return null;
}

/** SSRF guard for scanner endpoints (§17/§71): private ranges are allowed
 *  ONLY when the server-side endpoint configuration explicitly marks the
 *  deployment as an approved internal one; hard-blocked ranges never are. */
export function assertScannerEndpointAllowed(baseUrl: string, approvedInternal?: boolean): string {
  let u: URL;
  try {
    u = new URL(baseUrl);
  } catch {
    throw new AdapterConfigurationError(`Scanner endpoint is not a valid URL in server configuration`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new AdapterConfigurationError(`Scanner endpoint protocol ${u.protocol} is not allowed`);
  }
  if (u.username || u.password) {
    throw new AdapterConfigurationError("Scanner endpoint must not embed credentials — use a credential reference (§20)");
  }
  const host = u.hostname;
  const hard = hardBlockedReason(host);
  if (hard) throw new AdapterConfigurationError(`Scanner endpoint rejected: ${hard}`);
  const blocked = blockedTargetReason(host);
  if (blocked && !approvedInternal) {
    throw new AdapterConfigurationError(`Scanner endpoint rejected: ${blocked} — internal scanner endpoints require an explicitly approved internal deployment in server configuration (§71)`);
  }
  if (blocked && approvedInternal && u.protocol !== "https:" && process.env.DSRCLONE_ALLOW_HTTP_SCANNER !== "true") {
    // Approved internal deployments may use http only when the operator
    // explicitly opts in server-side; default stays https-or-nothing.
    throw new AdapterConfigurationError("Scanner endpoint rejected: http is allowed for approved internal deployments only with DSRCLONE_ALLOW_HTTP_SCANNER=true in server configuration");
  }
  return u.toString().replace(/\/$/, "");
}

/** Production transport over fetch. Redirects are never followed — a
 *  scanner endpoint redirecting elsewhere is a configuration problem, not
 *  an instruction (§17). This transport runs only against endpoints an
 *  administrator resolved from server configuration. */
export class HttpScannerTransport implements ScannerTransport {
  async request(input: { baseUrl: string; approvedInternal?: boolean; request: ConnectorTransportRequest }): Promise<ConnectorTransportResponse> {
    const base = assertScannerEndpointAllowed(input.baseUrl, input.approvedInternal);
    const qs = input.request.query ? `?${new URLSearchParams(input.request.query).toString()}` : "";
    const url = `${base}${input.request.path.startsWith("/") ? "" : "/"}${input.request.path}${qs}`;
    const started = Date.now();
    const res = await fetch(url, {
      method: input.request.method,
      headers: input.request.headers,
      ...(input.request.body !== undefined ? { body: input.request.body } : {}),
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
    const body = await res.text();
    return { status: res.status, body, latencyMs: Date.now() - started };
  }
}

export interface FixtureRoute {
  method?: "GET" | "POST";
  /** Path prefix or RegExp matched against the request path. */
  match: string | RegExp;
  respond: (req: ConnectorTransportRequest) => { status?: number; body: string | unknown };
}

/** Recorded-response transport for tests (§64–§67): every request is
 *  recorded (so tests can prove scope was configured and no secret leaked
 *  into URLs), and unmatched routes answer 404 — a fixture can never
 *  silently "succeed" at an interaction it did not record. */
export class FixtureScannerTransport implements ScannerTransport {
  readonly calls: Array<{ baseUrl: string; request: ConnectorTransportRequest }> = [];
  constructor(private readonly routes: FixtureRoute[]) {}
  async request(input: { baseUrl: string; approvedInternal?: boolean; request: ConnectorTransportRequest }): Promise<ConnectorTransportResponse> {
    this.calls.push({ baseUrl: input.baseUrl, request: input.request });
    for (const route of this.routes) {
      if (route.method && route.method !== input.request.method) continue;
      const matched = typeof route.match === "string" ? input.request.path.startsWith(route.match) : route.match.test(input.request.path);
      if (!matched) continue;
      const r = route.respond(input.request);
      return { status: r.status ?? 200, body: typeof r.body === "string" ? r.body : JSON.stringify(r.body), latencyMs: 1 };
    }
    return { status: 404, body: JSON.stringify({ error: "fixture route not found", path: input.request.path }), latencyMs: 1 };
  }
}

// ------------------------------- Base connector -------------------------------

export interface ConnectorDeps {
  instances: ScannerInstanceProvider;
  endpoints: EndpointResolver;
  secrets: SecretResolver;
  transport: ScannerTransport;
  sessions?: SessionProfileProvider;
  budget?: Partial<ProxyBudget>;
}

let contextCounter = 0;

export abstract class BaseScannerConnector implements InteractiveScannerConnector {
  abstract readonly product: ScannerProduct;
  protected readonly contexts = new Map<string, ScannerContextRecord>();
  protected connectedInstanceId: string | undefined;
  protected readonly budget: ProxyBudget;

  protected constructor(protected readonly deps: ConnectorDeps) {
    this.budget = clampProxyBudget(deps.budget);
  }

  get slug(): string { return PRODUCT_SLUGS[this.product]; }

  /** Session profile records (metadata only) for this deployment. */
  get sessionProfiles(): SessionProfileProvider | undefined { return this.deps.sessions; }

  /** Detected capabilities for one deployment (§14): what the admin
   *  declared ∩ what this product can ever do. IMPORT_ONLY deployments
   *  keep only import capabilities — they never receive live traffic. */
  detectedCapabilities(instance: ScannerInstanceRecord): Capability[] {
    const supported = PRODUCT_CAPABILITIES[this.product];
    const declared = instance.declaredCapabilities.filter((c) => supported.includes(c));
    if (instance.deploymentType === "IMPORT_ONLY") {
      // Prompt 11: vulnerability scanners contribute SCAN_RESULT_IMPORT
      // in import-only mode — they never receive live traffic either.
      return declared.filter((c) => c === "ISSUE_IMPORT" || c === "SITE_MAP_IMPORT" || c === "ENDPOINT_IMPORT" || c === "SCAN_RESULT_IMPORT");
    }
    return declared;
  }

  protected async instanceById(instanceId?: string): Promise<ScannerInstanceRecord | null> {
    if (instanceId) return this.deps.instances.getById(instanceId);
    const enabled = await this.deps.instances.listEnabled(this.product);
    return enabled[0] ?? null;
  }

  async checkAvailability(): Promise<boolean> {
    const instance = await this.instanceById(this.connectedInstanceId);
    if (!instance || !instance.enabled) return false;
    if (instance.deploymentType === "IMPORT_ONLY") return true; // import needs no live service
    const health = await this.healthCheck(instance.id);
    return health.status === "HEALTHY" || health.status === "DEGRADED";
  }

  /**
   * Health (§53/§66): layered and honest —
   *  no instance → NOT_CONFIGURED (a state, not an error);
   *  instance without a resolvable endpoint → MISCONFIGURED;
   *  declared credential reference that does not resolve → MISCONFIGURED;
   *  transport failure → UNAVAILABLE;
   *  reachable but unexpected → DEGRADED;
   *  product version confirmed → HEALTHY.
   */
  async healthCheck(instanceId?: string): Promise<ScannerHealth> {
    const checkedAt = new Date().toISOString();
    const instance = await this.instanceById(instanceId);
    if (!instance) {
      return { status: "NOT_CONFIGURED", capabilities: [], detail: `No ${this.product} scanner instance is registered — an administrator must register one before this connector can run (§16)`, checkedAt };
    }
    const capabilities = this.detectedCapabilities(instance);
    if (!instance.enabled) {
      return { status: "UNAVAILABLE", capabilities, detail: `Scanner instance "${instance.name}" is disabled`, checkedAt };
    }
    if (instance.deploymentType === "IMPORT_ONLY") {
      return { status: "HEALTHY", capabilities, detail: "Import-only instance: health is configuration-level; issue/site-map imports are accepted through the import path", checkedAt };
    }
    if (instance.credentialReference) {
      const secret = await this.deps.secrets.resolve(instance.credentialReference);
      if (!secret) {
        return { status: "MISCONFIGURED", capabilities, detail: `Credential reference ${instance.credentialReference} does not resolve in this environment — the instance cannot authenticate (§20)`, checkedAt };
      }
    }
    const endpoint = await this.deps.endpoints.resolve(instance.endpointReference);
    if (!endpoint) {
      return { status: "MISCONFIGURED", capabilities, detail: `Endpoint reference ${instance.endpointReference} is not present in server configuration — scanner endpoints are resolved only from trusted admin configuration (§17)`, checkedAt };
    }
    try {
      const probe = await this.probe(instance, endpoint.baseUrl, endpoint.approvedInternal);
      return {
        status: probe.version ? "HEALTHY" : "DEGRADED",
        ...(probe.version ? { version: probe.version } : {}),
        ...(probe.licenseState ? { licenseState: probe.licenseState } : {}),
        capabilities,
        latencyMs: probe.latencyMs,
        detail: probe.version ? `${this.product} ${probe.version} reachable` : `Reachable but the product did not confirm its version — capabilities are as declared, treat as degraded (§53)`,
        checkedAt,
      };
    } catch (err) {
      return { status: "UNAVAILABLE", capabilities, detail: `Probe failed: ${err instanceof Error ? err.message : "unknown error"}`, checkedAt };
    }
  }

  /** Product-specific version probe against the resolved endpoint. */
  protected abstract probe(instance: ScannerInstanceRecord, baseUrl: string, approvedInternal?: boolean): Promise<{ version?: string; licenseState?: string; latencyMs: number }>;

  async connect(instanceId: string): Promise<void> {
    const instance = await this.deps.instances.getById(instanceId);
    if (!instance || instance.product !== this.product) {
      throw new AdapterUnavailableError(`${this.slug}: scanner instance ${instanceId} is not a registered ${this.product} instance`);
    }
    if (!instance.enabled) throw new AdapterUnavailableError(`${this.slug}: scanner instance "${instance.name}" is disabled`);
    this.connectedInstanceId = instanceId;
  }

  async disconnect(): Promise<void> {
    this.connectedInstanceId = undefined;
  }

  async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    if (config.instanceId !== undefined && typeof config.instanceId !== "string") {
      throw new AdapterConfigurationError("instanceId must be a scanner instance id string");
    }
    if (config.sessionProfileId !== undefined && typeof config.sessionProfileId !== "string") {
      throw new AdapterConfigurationError("sessionProfileId must be a session profile id string");
    }
  }

  /**
   * Create an isolated per-assessment context (§6). Scope is configured
   * from the persisted ScopeRules at creation: every included target must
   * be in scope (ScopeMatcher verdict), or creation is refused — a
   * connector can never widen scope.
   */
  async createContext(input: {
    instanceId: string; workspaceId: string; assessmentId: string; scanId?: string;
    scopeRules: ScopeRules; targetBaseUrls: string[]; sessionProfile?: SessionProfileRecord;
  }): Promise<ScannerContextRecord> {
    const instance = await this.deps.instances.getById(input.instanceId);
    if (!instance || instance.product !== this.product || !instance.enabled) {
      throw new AdapterUnavailableError(`${this.slug}: scanner instance ${input.instanceId} is unavailable`);
    }
    const matcher = new ScopeMatcher(input.scopeRules);
    for (const url of input.targetBaseUrls) {
      if (!matcher.isUrlAllowed(url)) {
        throw new AdapterConfigurationError(`${this.slug}: context target ${url} is outside the approved scope — refusing to create a context that exceeds scope (§6)`);
      }
    }
    if (input.sessionProfile && input.sessionProfile.workspaceId !== input.workspaceId) {
      throw new AdapterConfigurationError(`${this.slug}: session profile belongs to another workspace — tenant isolation forbids cross-workspace sessions (§6/§69)`);
    }
    const id = `ctx-${this.product.toLowerCase()}-${++contextCounter}`;
    const context: ScannerContextRecord = {
      id,
      instanceId: input.instanceId,
      product: this.product,
      workspaceId: input.workspaceId,
      assessmentId: input.assessmentId,
      ...(input.scanId ? { scanId: input.scanId } : {}),
      vendorContextName: `dsrclone-${input.assessmentId.slice(0, 8)}-${id}`,
      includedTargets: [...input.targetBaseUrls],
      excludedTargets: [...input.scopeRules.excludeHosts],
      ...(input.sessionProfile ? { sessionProfileId: input.sessionProfile.id } : {}),
      status: "ACTIVE",
      createdAt: new Date().toISOString(),
    };
    this.contexts.set(id, context);
    await this.vendorCreateContext(context, instance).catch(async (err) => {
      this.contexts.delete(id);
      throw err;
    });
    return context;
  }

  async configureScope(contextId: string, scopeRules: ScopeRules, targetBaseUrls: string[]): Promise<void> {
    const context = this.requireContext(contextId);
    const matcher = new ScopeMatcher(scopeRules);
    for (const url of targetBaseUrls) {
      if (!matcher.isUrlAllowed(url)) {
        throw new AdapterConfigurationError(`${this.slug}: scope configuration target ${url} is outside the approved scope`);
      }
    }
    context.includedTargets = [...new Set([...context.includedTargets, ...targetBaseUrls])];
    context.excludedTargets = [...new Set([...context.excludedTargets, ...scopeRules.excludeHosts])];
    const instance = await this.deps.instances.getById(context.instanceId);
    if (instance) await this.vendorConfigureScope(context, instance, scopeRules);
  }

  /** Authentication is configured by REFERENCE only (§20/§21): the secret
   *  is resolved inside this trusted boundary at vendor-call time; the
   *  context records WHICH profile is bound, never any secret material.
   *  No login script of any kind is accepted or executed (§19). */
  async configureAuthentication(contextId: string, sessionProfile?: SessionProfileRecord): Promise<void> {
    const context = this.requireContext(contextId);
    if (!sessionProfile) return;
    if (sessionProfile.workspaceId !== context.workspaceId) {
      throw new AdapterConfigurationError(`${this.slug}: session profile belongs to another workspace (§69)`);
    }
    context.sessionProfileId = sessionProfile.id;
  }

  async cancel(contextId: string): Promise<void> {
    this.requireContext(contextId);
    // Passive pipelines have no long-running vendor job to abort in this
    // phase; cancellation is honoured by the worker between stages. The
    // context is destroyed so nothing lingers (§6 isolation).
    await this.cleanup(contextId);
  }

  async cleanup(contextId: string): Promise<void> {
    const context = this.contexts.get(contextId);
    if (!context) return;
    const instance = await this.deps.instances.getById(context.instanceId);
    if (instance) await this.vendorDestroyContext(context, instance).catch(() => undefined);
    context.status = "DESTROYED";
    context.destroyedAt = new Date().toISOString();
    this.contexts.delete(contextId);
  }

  /** Active scanning (§8/§12): the gate decides; the connector NEVER
   *  starts an active scan in this phase even when the gate passes — the
   *  capability is prepared and approval-gated, and enablement lands with
   *  the future active-testing phase. A passing gate is reported as
   *  "eligible", not "started". */
  async startActiveScan(_contextId: string, gate: ActiveScanGateInput): Promise<{ started: boolean; decision: ActiveScanGateDecision }> {
    const decision = evaluateActiveScanGate(gate);
    if (!decision.allowed) return { started: false, decision };
    return {
      started: false,
      decision: { ...decision, message: "Approval gate passed, but automated active scanning is not enabled in this phase — capability remains disabled by default (§8/§38)" },
    };
  }

  protected requireContext(contextId: string): ScannerContextRecord {
    const context = this.contexts.get(contextId);
    if (!context || context.status !== "ACTIVE") {
      throw new AdapterConfigurationError(`${this.slug}: scanner context ${contextId} does not exist or is destroyed`);
    }
    return context;
  }

  protected contextById(contextId: string): ScannerContextRecord {
    return this.requireContext(contextId);
  }

  /** Authorized transport call: resolves endpoint + secret per call.
   *  Secrets travel as headers only, for this call only (§5/§20). */
  protected async call(
    instance: ScannerInstanceRecord,
    request: ConnectorTransportRequest,
    secretHeader?: string,
  ): Promise<{ status: number; body: string; latencyMs: number }> {
    const endpoint = await this.deps.endpoints.resolve(instance.endpointReference);
    if (!endpoint) {
      throw new AdapterUnavailableError(`${this.slug}: endpoint reference ${instance.endpointReference} is not configured on this host (MISCONFIGURED instance)`);
    }
    const headers: Record<string, string> = { ...(request.headers ?? {}) };
    if (instance.credentialReference && secretHeader) {
      const secret = await this.deps.secrets.resolve(instance.credentialReference);
      if (!secret) {
        throw new AdapterUnavailableError(`${this.slug}: credential reference ${instance.credentialReference} does not resolve (MISCONFIGURED instance)`);
      }
      headers[secretHeader] = secret;
    }
    return this.deps.transport.request({
      baseUrl: endpoint.baseUrl,
      ...(endpoint.approvedInternal ? { approvedInternal: true } : {}),
      request: { ...request, headers },
    });
  }

  // Product hooks — default no-ops for products whose vendor API has no
  // context concept in the configured deployment (import-only flows).
  protected async vendorCreateContext(_context: ScannerContextRecord, _instance: ScannerInstanceRecord): Promise<void> { /* per-product */ }
  protected async vendorConfigureScope(_context: ScannerContextRecord, _instance: ScannerInstanceRecord, _scope: ScopeRules): Promise<void> { /* per-product */ }
  protected async vendorDestroyContext(_context: ScannerContextRecord, _instance: ScannerInstanceRecord): Promise<void> { /* per-product */ }

  abstract importEndpoints(contextId: string): Promise<{ endpoints: NormalizedEndpoint[]; transactions: NormalizedHttpTransaction[]; webSockets: NormalizedWebSocket[] }>;
  abstract startPassiveAnalysis(contextId: string): Promise<void>;
  abstract getProgress(contextId: string): Promise<{ phase: string; percent: number; detail?: string }>;
  abstract getIssues(contextId: string): Promise<NormalizedVulnFinding[]>;
  abstract exportArtifacts(contextId: string): Promise<{ artifactKind: string; reference: string }[]>;
}

/** Session validity assessment (§22/§23): a session is VALID only when a
 *  transaction against the profile's known authenticated URL shows the
 *  expected signal. Login redirects / 401 / 403 mean EXPIRED — the scan
 *  continues with the anonymous view and is marked accordingly; it never
 *  retries credentials endlessly (§23). */
export function assessSession(
  profile: SessionProfileRecord | undefined,
  transactions: NormalizedHttpTransaction[],
): "NOT_APPLICABLE" | "VALID" | "EXPIRED" | "UNKNOWN" {
  if (!profile || profile.type === "ANONYMOUS") return "NOT_APPLICABLE";
  const probeUrl = profile.validation?.authenticatedUrl;
  if (!probeUrl) return "UNKNOWN";
  const tx = [...transactions].reverse().find((t) => t.url.startsWith(probeUrl));
  if (!tx) return "UNKNOWN";
  const response = tx.responseRedacted ?? "";
  if (tx.statusCode === 401 || tx.statusCode === 403) return "EXPIRED";
  if (tx.statusCode !== undefined && tx.statusCode >= 300 && tx.statusCode < 400 && /location:[^\n]*login/i.test(response)) return "EXPIRED";
  if (profile.validation?.expectedMarker && !response.includes(profile.validation.expectedMarker)) return "EXPIRED";
  const expected = profile.validation?.expectedStatus ?? 200;
  if (tx.statusCode === expected) return "VALID";
  return "UNKNOWN";
}

/** Logout guard for crawl inputs (§47): URLs a connector-driven crawl
 *  must never request with an authenticated session. */
export function filterLogoutUrls(urls: string[]): { kept: string[]; dropped: string[] } {
  const kept: string[] = [];
  const dropped: string[] = [];
  for (const u of urls) (isLogoutUrl(u) ? dropped : kept).push(u);
  return { kept, dropped };
}

/** Merge one product's parsed payload into a ParsedProxy accumulator. */
export function mergeParsedProxy(into: ParsedProxy, from: ParsedProxy): ParsedProxy {
  into.findings.push(...from.findings);
  into.endpoints.push(...from.endpoints);
  into.transactions.push(...from.transactions);
  into.webSockets.push(...from.webSockets);
  into.observations.push(...from.observations);
  into.warnings.push(...from.warnings);
  into.records += from.records;
  return into;
}

export { emptyParsedProxy };
