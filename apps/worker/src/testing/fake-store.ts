import { CidrPolicyService, JwtToolAdapter, MockSecurityAdapter, ToolRegistry, expandCidrTargets } from "@dsrclone/security-sdk";
import { buildScanPlan, type ScanPlan, type ScanEventRecord } from "@dsrclone/orchestration";
import type { ScopeRules } from "@dsrclone/validation";
import type { ExecutionContextRecord } from "../executors/stage-executor";
import type { ScanRunRecord, ScanRunStore } from "../consumers/dag-runner";
import { correlateProcessedFindings, processNormalizedResult, type ProcessedResult } from "../executors/result-processor";

/**
 * In-memory ScanRunStore for worker tests (Prompt 4 §56, extended Prompt 5):
 * the same shapes the Prisma store and BullMQ dispatcher implement, backed
 * by maps. Plans can be built against any registry (mock-only by default;
 * fixture-backed recon adapters for the Prompt 5 end-to-end scenarios).
 */

export const TEST_SCOPE: ScopeRules = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };
export const TEST_AUTH = {
  organizationId: "org-1", workspaceId: "ws-1", targetId: "t-1", targetOrganizationId: "org-1",
  assessmentId: "a-1", scanId: "scan-1", verificationStatus: "VERIFIED" as const,
  approvalStatus: "APPROVED" as const, requestedBy: "u-1",
};

export interface ExecRec { id: string; stageType: string; adapterSlug: string; status: string; patch: Record<string, unknown> }

export interface FakeStoreOptions {
  /** Registry the PLAN is built against (selection happens at plan time). */
  planRegistry?: ToolRegistry;
  healthBySlug?: Record<string, string>;
  executableSlugs?: string[];
  targetType?: "DOMAIN" | "WEB_APPLICATION" | "API" | "GRAPHQL" | "CIDR" | "IP_ADDRESS";
  /** Prompt 10: network target state mirroring the Prisma store — the
   *  CIDR/IP target, its scope, the store-resolved Masscan approval and
   *  the authorized capture reference for tshark analysis. */
  networkTarget?: { targetValue: string; targetHost: string; scope: ScopeRules; masscanApproved?: boolean; captureRef?: string };
  /** Prompt 8: scanner bindings per connector slug, mirroring the Prisma
   *  store's workspace resolution. Absent slug = NOT_CONFIGURED. */
  scannerBySlug?: Record<string, { instanceId: string; sessionProfileId?: string }>;
  /** Prompt 9: the guarded-import + auth-context state the API stages
   *  read, mirroring the Prisma store's import records: specification
   *  locations for Schemathesis, imported operations for its policy
   *  filter, obviously-fake JWTs for the inspection hook, imported
   *  specification counts and registered auth contexts. */
  apiFixtures?: {
    specUrls?: string[];
    operations?: string[];
    jwtTokens?: string[];
    specifications?: { operations: number }[];
    authContexts?: { role: string }[];
  };
}

export class FakeStore implements ScanRunStore {
  plan: ScanPlan;
  scanStatus = "QUEUED";
  progress = 0;
  stages = new Map<string, string>();
  executions = new Map<string, ExecRec>();
  events: ScanEventRecord[] = [];
  assets: ProcessedResult["assets"] = [];
  findings: ProcessedResult["findings"] = [];
  endpoints: ProcessedResult["endpoints"] = [];
  services: ProcessedResult["services"] = [];
  technologies: ProcessedResult["technologies"] = [];
  parameters: ProcessedResult["parameters"] = [];
  forms: ProcessedResult["forms"] = [];
  transactions: ProcessedResult["transactions"] = [];
  webSockets: ProcessedResult["webSockets"] = [];
  apiServices: ProcessedResult["apiServices"] = [];
  graphqlServices: ProcessedResult["graphqlServices"] = [];
  jwtProfiles: ProcessedResult["jwtProfiles"] = [];
  packetCaptures: ProcessedResult["packetCaptures"] = [];
  networkChunks: Array<{ chunkId: string; rangeStart: string; rangeEnd: string; hostCount: number; status: string }> = [];
  networkTarget: FakeStoreOptions["networkTarget"];
  apiFixtures: NonNullable<FakeStoreOptions["apiFixtures"]> = {};
  scannerBySlug: Record<string, { instanceId: string; sessionProfileId?: string }> = {};
  deadLetters: unknown[] = [];
  reportPending = false;
  paused = false;
  cancelled = false;
  simulationByStage: Record<string, ExecutionContextRecord["simulation"]> = {};
  verified = true;
  targetType: "DOMAIN" | "WEB_APPLICATION" | "API" | "GRAPHQL" | "CIDR" | "IP_ADDRESS";

  // (constructor assigns targetType from opts)

  constructor(profile: "PASSIVE_RECON" | "WEB_BASELINE" | "WEB_COMPREHENSIVE" | "API_ASSESSMENT" | "NETWORK_DISCOVERY" | "NETWORK_BASELINE" | "NETWORK_COMPREHENSIVE" | "NETWORK_INTERNAL" | "NETWORK_ASSESSMENT", opts: FakeStoreOptions = {}) {
    this.targetType = opts.targetType ?? "DOMAIN";
    this.scannerBySlug = opts.scannerBySlug ?? {};
    this.apiFixtures = opts.apiFixtures ?? {};
    this.networkTarget = opts.networkTarget;
    const registry = opts.planRegistry ?? (() => { const r = new ToolRegistry(); r.register(new MockSecurityAdapter()); return r; })();
    this.plan = buildScanPlan({
      scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
      profile, targetType: opts.targetType ?? "DOMAIN",
      targetValue: opts.networkTarget?.targetValue ?? "example.com", targetHost: opts.networkTarget?.targetHost ?? "example.com",
      scope: opts.networkTarget?.scope ?? TEST_SCOPE, targetVerified: true, assessmentApproved: true, registry,
      selection: {
        executableSlugs: opts.executableSlugs ?? ["mock", "local-echo"],
        ...(opts.healthBySlug ? { healthBySlug: opts.healthBySlug } : {}),
      },
    }).plan;
    for (const s of this.plan.stages) this.stages.set(s.type, s.dependencies.length === 0 ? "READY" : "BLOCKED");
    this.simulationByStage["PASSIVE_RECON"] = { fixture: true };
  }

  private gate() {
    return {
      auth: TEST_AUTH, targetHost: this.networkTarget?.targetHost ?? "example.com", scopeRules: this.networkTarget?.scope ?? TEST_SCOPE, targetExists: true,
      targetWorkspaceId: "ws-1", workspaceId: "ws-1",
      targetVerified: this.verified, assessmentApproved: true, scopeValid: true,
    };
  }

  async loadScanRun(): Promise<ScanRunRecord> {
    return { plan: this.plan, scanStatus: this.scanStatus, progress: this.progress, gate: this.gate() };
  }
  async stageStatuses(): Promise<Map<string, string>> { return new Map(this.stages); }
  async updateScan(_id: string, patch: Record<string, unknown>): Promise<void> {
    if (typeof patch.status === "string") this.scanStatus = patch.status;
    if (typeof patch.progress === "number") this.progress = patch.progress;
  }
  async updateStage(_id: string, stageType: string, patch: Record<string, unknown>): Promise<void> {
    if (typeof patch.status === "string") this.stages.set(stageType, patch.status);
  }
  async ensureExecution(_scanId: string, stageType: string, adapterSlug: string, _attempt = 1): Promise<{ id: string; status: string }> {
    const id = `exec-${stageType}-${adapterSlug}`;
    if (!this.executions.has(id)) this.executions.set(id, { id, stageType, adapterSlug, status: "QUEUED", patch: {} });
    return { id, status: this.executions.get(id)!.status };
  }
  async markReportPending(): Promise<void> { this.reportPending = true; }
  async isPaused(): Promise<boolean> { return this.paused; }
  async isCancelled(): Promise<boolean> { return this.cancelled || this.scanStatus === "CANCELLED"; }

  async loadExecutionContext(executionId: string): Promise<ExecutionContextRecord | null> {
    const exec = this.executions.get(executionId);
    if (!exec) return null;
    const planned = this.plan.stages.find((s) => s.type === exec.stageType)!;
    return {
      executionId, scanId: "scan-1", stageId: exec.stageType, workspaceId: "ws-1", organizationId: "org-1",
      adapterSlug: exec.adapterSlug, status: exec.status, attempt: 1, timeoutSeconds: planned.timeoutSeconds,
      targetType: this.targetType, targetValue: this.networkTarget?.targetValue ?? "example.com", targetHost: this.networkTarget?.targetHost ?? "example.com", scopeRules: this.networkTarget?.scope ?? TEST_SCOPE,
      auth: TEST_AUTH, targetExists: true, targetWorkspaceId: "ws-1",
      targetVerified: this.verified, assessmentApproved: true, scopeValid: true,
      networkCapable: planned.networkCapable,
      profile: this.plan.profile,
      assessmentId: "a-1",
      masscanApproved: this.networkTarget?.masscanApproved,
      captureRef: this.networkTarget?.captureRef,
      scanner: this.scannerBySlug[exec.adapterSlug],
      simulation: this.simulationByStage[exec.stageType],
      // Discovery inputs (§26): persisted in-scope inventory so far.
      stageInputs: {
        hosts: [...new Set(this.assets.filter((a) => a.scopeStatus === "IN_SCOPE").map((a) => a.host))],
        urls: [...new Set(this.endpoints.filter((e) => e.scopeStatus === "IN_SCOPE").map((e) => e.url))],
        technologies: [...new Set(this.technologies.map((t) => t.name))],
        // TLS services (§13): TLS-looking services on in-scope assets.
        services: [...new Set(this.services
          .filter((s) => s.scheme === "https" || [443, 8443].includes(s.port) || ["https", "ssl", "tls"].includes(s.name))
          .map((s) => `${s.host}:${s.port}`))],
        // Prompt 9: imported specification locations + operations from
        // the guarded import records (fixtures here, import store in
        // production) — the executor derives schemathesis config from
        // these, never from clients.
        specUrls: this.apiFixtures.specUrls ?? [],
        operations: this.apiFixtures.operations ?? [],
      },
    };
  }

  /** Prompt 7 hooks mirroring the Prisma store's pipeline behaviour. */
  correlatedFindings: ProcessedResult["findings"] = [];
  findingStats: Record<string, unknown> | null = null;

  async summarizeFindings(): Promise<Record<string, unknown> | null> {
    if (this.findings.length === 0) return null;
    const bySeverity: Record<string, number> = {};
    for (const f of this.findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    return { totalFindings: this.findings.length, bySeverity };
  }

  async correlateScanFindings(): Promise<{ canonical: number; duplicates: number; stats: Record<string, unknown> } | null> {
    if (this.findings.length === 0) return null;
    const { findings, stats } = correlateProcessedFindings(this.findings, { maxFindings: 1000 });
    this.correlatedFindings = findings;
    this.findingStats = stats as unknown as Record<string, unknown>;
    return { canonical: findings.length, duplicates: stats.duplicatesMerged, stats: stats as unknown as Record<string, unknown> };
  }

  async recalculateFindingRisk(): Promise<{ updated: number } | null> {
    if (this.correlatedFindings.length === 0) return null;
    return { updated: this.correlatedFindings.length };
  }
  async updateExecution(id: string, patch: Record<string, unknown>): Promise<void> {
    const exec = this.executions.get(id);
    if (!exec) return;
    Object.assign(exec.patch, patch);
    if (typeof patch.status === "string") exec.status = patch.status;
  }
  async recordEvent(event: ScanEventRecord): Promise<void> { this.events.push(event); }
  async persistResult(_scanId: string, _executionId: string, processed: ProcessedResult): Promise<{ assets: number; findings: number; endpoints: number; services: number; technologies: number; parameters: number; forms: number; transactions: number; webSockets: number; apiServices: number; graphqlServices: number; jwtProfiles: number; packetCaptures: number }> {
    // Assets merge by host (one canonical row, provenance unioned) —
    // mirrors the Prisma store's upsert behaviour.
    for (const a of processed.assets) {
      const existing = this.assets.find((x) => x.host === a.host);
      if (existing) {
        existing.sources = [...new Set([...existing.sources, ...a.sources])];
        existing.ip ??= a.ip;
        existing.osHint ??= a.osHint;
        existing.osConfidence ??= a.osConfidence;
      } else this.assets.push(a);
    }
    this.findings.push(...processed.findings);
    this.endpoints.push(...processed.endpoints);
    // Services merge by (host, port, protocol) with PortResultAggregator
    // semantics (§49): provenance unioned, richer evidence gap-filled,
    // OPEN outranks CLOSED — mirrors the Prisma store's merge upsert.
    const stateRank: Record<string, number> = { OPEN: 4, OPEN_FILTERED: 3, UNKNOWN: 2, FILTERED: 1, CLOSED: 0 };
    for (const s of processed.services) {
      const existing = this.services.find((x) => x.host === s.host && x.port === s.port && x.protocol === s.protocol);
      if (existing) {
        existing.sources = [...new Set([...(existing.sources ?? []), ...(s.sources ?? [])])].sort();
        existing.product ??= s.product;
        existing.version ??= s.version;
        existing.cpe ??= s.cpe;
        existing.banner ??= s.banner;
        if (s.tls !== undefined) existing.tls = existing.tls ?? s.tls;
        existing.confidence = Math.max(existing.confidence ?? 0, s.confidence ?? 0) || undefined;
        if ((stateRank[s.state ?? "UNKNOWN"] ?? 0) > (stateRank[existing.state ?? "UNKNOWN"] ?? 0)) existing.state = s.state;
        if ((!existing.name || existing.name === "unknown") && s.name) existing.name = s.name;
      } else this.services.push(s);
    }
    this.technologies.push(...processed.technologies);
    this.parameters.push(...processed.parameters);
    this.forms.push(...processed.forms);
    this.transactions.push(...processed.transactions);
    this.webSockets.push(...processed.webSockets);
    this.apiServices.push(...processed.apiServices);
    this.graphqlServices.push(...processed.graphqlServices);
    this.jwtProfiles.push(...processed.jwtProfiles);
    this.packetCaptures.push(...processed.packetCaptures);
    return { assets: processed.assets.length, findings: processed.findings.length, endpoints: processed.endpoints.length, services: processed.services.length, technologies: processed.technologies.length, parameters: processed.parameters.length, forms: processed.forms.length, transactions: processed.transactions.length, webSockets: processed.webSockets.length, apiServices: processed.apiServices.length, graphqlServices: processed.graphqlServices.length, jwtProfiles: processed.jwtProfiles.length, packetCaptures: processed.packetCaptures.length };
  }

  /** Prompt 10 platform hook mirroring the Prisma store: bounded target
   *  expansion over the scan's CIDR target (§5/§62). */
  async expandNetworkTargets(): Promise<{ mode: string; hosts: number; chunks: number; totalHosts: number } | null> {
    const value = this.networkTarget?.targetValue;
    if (!value) return null;
    const verdict = new CidrPolicyService().evaluate(value, { administratorApproved: false });
    if (verdict && verdict.approval === "DENY") {
      return { mode: "DENIED", hosts: 0, chunks: 0, totalHosts: verdict.hostCount };
    }
    const expansion = expandCidrTargets(value);
    if (!expansion) return null;
    this.networkChunks = expansion.chunks.map((c) => ({ chunkId: c.chunkId, rangeStart: c.rangeStart, rangeEnd: c.rangeEnd, hostCount: c.hostCount, status: "PENDING" }));
    return expansion.kind === "LIST"
      ? { mode: "LIST", hosts: expansion.hosts.length, chunks: expansion.chunks.length, totalHosts: expansion.hosts.length }
      : { mode: "RANGES", hosts: 0, chunks: expansion.chunks.length, totalHosts: expansion.totalHosts };
  }

  /** Prompt 9 platform hooks mirroring the Prisma store's behaviour. */
  async consolidateApiServices(): Promise<{ services: number; endpoints: number } | null> {
    if (this.apiServices.length === 0 && this.endpoints.length === 0) return null;
    return { services: this.apiServices.length, endpoints: this.endpoints.length };
  }

  async summarizeApiSpecifications(): Promise<{ specifications: number; operations: number } | null> {
    const specs = this.apiFixtures.specifications ?? [];
    if (specs.length === 0) return null;
    return { specifications: specs.length, operations: specs.reduce((n, s) => n + s.operations, 0) };
  }

  async mapApiAuthentication(): Promise<{ contexts: number; servicesWithAuth: number } | null> {
    const contexts = this.apiFixtures.authContexts ?? [];
    const servicesWithAuth = this.apiServices.filter((s) => s.authenticationType && s.authenticationType !== "NONE").length;
    if (contexts.length === 0 && servicesWithAuth === 0) return null;
    return { contexts: contexts.length, servicesWithAuth };
  }

  async analyzeJwtProfiles(): Promise<{ tokens: number; findings: number } | null> {
    const tokens = this.apiFixtures.jwtTokens ?? [];
    if (tokens.length === 0) return null;
    const adapter = new JwtToolAdapter();
    const parsed = adapter.inspectTokens({ tokens, host: "example.com" });
    const normalized = await adapter.normalize(parsed);
    const processed = processNormalizedResult(normalized, { scopeRules: TEST_SCOPE, toolExecutionId: "platform-jwt", toolSlug: "jwt-tool" });
    this.jwtProfiles.push(...processed.jwtProfiles);
    this.findings.push(...processed.findings);
    return { tokens: processed.jwtProfiles.length, findings: processed.findings.length };
  }

  async inventoryWebSockets(): Promise<{ webSockets: number; authenticated: number } | null> {
    if (this.webSockets.length === 0) return null;
    return { webSockets: this.webSockets.length, authenticated: this.webSockets.filter((w) => w.authPresent).length };
  }
  async recordDeadLetter(entry: unknown): Promise<void> { this.deadLetters.push(entry); }
}
