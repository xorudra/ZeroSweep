import {
  API_SLUGS, NucleiAdapter, PROXY_SLUGS, RECON_SLUGS, VULN_SLUGS, WEB_DISCOVERY_SLUGS, ScopeMatcher, ToolRegistry,
  approvedReviewIdsForProfile, evaluateToolPolicy, isScannerConnectorAdapter, type AuthorizationContext,
} from "@dsrclone/security-sdk";
import type { ScopeRules } from "@dsrclone/validation";
import {
  assertExecutionTransition, classifyError, evaluateAuthorizationGate,
  idempotencyKey, makeEvent, type ScanEventRecord,
} from "@dsrclone/orchestration";
import { InMemoryObjectStore, rawArtifactKey, type ObjectStore } from "../artifacts/object-store";
import { processNormalizedResult, type ProcessedResult } from "./result-processor";

/**
 * Stage executor (Prompt 4 §20): the worker — never the API — runs adapters.
 * It loads TRUSTED state through the store (queue payloads carry IDs only,
 * §14), re-evaluates authorization + scope + policy immediately before
 * execution (§11–§12), runs the adapter lifecycle, stores the raw artifact in
 * object storage, parses, normalizes, and persists through the store.
 * Executable adapters: the Phase 4 mock/local-echo pair, the Prompt 5
 * recon adapters (subfinder … katana) and the Prompt 6 web-discovery
 * adapters (ffuf, feroxbuster, gobuster, wfuzz, arjun). Real adapters run
 * ONLY through their validated plans and only when their binary is
 * actually present — otherwise policy denies with TOOL_UNAVAILABLE and
 * orchestration degrades the capability instead of crashing (§55–§56).
 */

export const EXECUTABLE_SLUGS = ["mock", "local-echo", ...RECON_SLUGS, ...WEB_DISCOVERY_SLUGS, ...VULN_SLUGS, ...PROXY_SLUGS, ...API_SLUGS] as const;

export interface ExecutionContextRecord {
  executionId: string;
  scanId: string;
  stageId: string; // stage TYPE (plan stage id)
  workspaceId: string;
  organizationId: string;
  adapterSlug: string;
  status: string;
  attempt: number;
  timeoutSeconds: number;
  targetType: string;
  targetValue: string;
  targetHost: string;
  scopeRules: ScopeRules;
  auth: AuthorizationContext;
  targetExists: boolean;
  targetWorkspaceId: string;
  targetVerified: boolean;
  assessmentApproved: boolean;
  scopeValid: boolean;
  networkCapable: boolean;
  /** Discovery inputs produced by earlier stages (Prompt 5 §26): in-scope
   *  asset hostnames and endpoint URLs, loaded from persisted state by the
   *  store — never from queue payloads. Adapters receive only the fields
   *  their declared input schema accepts. */
  stageInputs?: {
    hosts: string[]; urls: string[]; technologies?: string[]; services?: string[];
    /** Prompt 9: imported specification locations + imported operations
     *  (encoded "METHOD path operationId?"), loaded by the store from the
     *  guarded import records — never from queue payloads (§15). */
    specUrls?: string[]; operations?: string[];
  };
  /** The scan's assessment profile (from the persisted plan) — drives
   *  Prompt 6 wordlist profile selection: WEB_BASELINE → SMALL, anything
   *  broader → STANDARD. COMPREHENSIVE is never selected automatically. */
  profile?: string;
  /** The scan's assessment id (trusted state, for connector context
   *  binding — Prompt 8 §6). */
  assessmentId?: string;
  /** Prompt 8 scanner binding, resolved by the STORE from admin-registered
   *  ScannerInstance rows for this workspace — never from queue payloads
   *  or client input (§16/§17). Absent instanceId = NOT_CONFIGURED. */
  scanner?: { instanceId?: string; sessionProfileId?: string };
  /** Deterministic test/simulation hooks (never set by clients). */
  simulation?: { delayMs?: number; failWith?: "TOOL_ERROR" | "TIMEOUT"; fixture?: boolean };
}

export interface ExecutionStore {
  loadExecutionContext(executionId: string): Promise<ExecutionContextRecord | null>;
  updateExecution(id: string, patch: Record<string, unknown>): Promise<void>;
  recordEvent(event: ScanEventRecord): Promise<void>;
  persistResult(scanId: string, executionId: string, processed: ProcessedResult): Promise<{ assets: number; findings: number; endpoints?: number; services?: number; technologies?: number; parameters?: number; forms?: number; transactions?: number; webSockets?: number; apiServices?: number; graphqlServices?: number; jwtProfiles?: number }>;
  recordDeadLetter(entry: { jobId: string; queue: string; scanId: string; stageId: string; executionId: string; errorCategory: string; errorMessage: string; attempts: number }): Promise<void>;
  isCancelled(scanId: string): Promise<boolean>;
}

export interface StageJobData {
  kind: "STAGE_EXECUTION";
  scanId: string;
  stageId: string;
  toolExecutionId: string;
  attempt: number;
}

export type StageExecutionOutcome =
  | { status: "COMPLETED"; assets: number; findings: number }
  | { status: "PARTIAL_DATA" } // synthesized by the DAG runner when some adapters of a stage completed (§55)
  | { status: "ALREADY_COMPLETED" }
  | { status: "DENIED"; reasonCode: string }
  | { status: "CANCELLED" }
  | { status: "FAILED" | "TIMED_OUT"; category: string };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class StageExecutor {
  private readonly objectStore: ObjectStore;

  constructor(
    private readonly registry: ToolRegistry,
    private readonly store: ExecutionStore,
    objectStore?: ObjectStore,
  ) {
    this.objectStore = objectStore ?? new InMemoryObjectStore();
  }

  async run(job: StageJobData): Promise<StageExecutionOutcome> {
    const ctx = await this.store.loadExecutionContext(job.toolExecutionId);
    if (!ctx) return { status: "FAILED", category: "CONFIGURATION" };
    const emit = (type: ScanEventRecord["type"], payload: ScanEventRecord["payload"]) =>
      this.store.recordEvent(makeEvent(ctx.scanId, ctx.workspaceId, type, payload));

    // Idempotency (§15): a duplicate delivery of a finished execution is a no-op.
    if (ctx.status === "COMPLETED") return { status: "ALREADY_COMPLETED" };
    if (await this.store.isCancelled(ctx.scanId)) {
      await this.transition(ctx, "CANCELLING").catch(() => undefined);
      await this.store.updateExecution(ctx.executionId, { status: "CANCELLED", completedAt: new Date() });
      return { status: "CANCELLED" };
    }

    try {
      await this.transition(ctx, "PREPARING");

      // --- Gates, re-evaluated with trusted state (§11–§12) ---
      const gate = evaluateAuthorizationGate({
        auth: ctx.auth, targetHost: ctx.targetHost, scopeRules: ctx.scopeRules,
        targetExists: ctx.targetExists, targetWorkspaceId: ctx.targetWorkspaceId, workspaceId: ctx.workspaceId,
        targetVerified: ctx.targetVerified, assessmentApproved: ctx.assessmentApproved, scopeValid: ctx.scopeValid,
      });
      if (!gate.allowed) {
        await emit(gate.reasonCode === "TARGET_OUT_OF_SCOPE" ? "scope.violation" : "policy.denied", { stageId: ctx.stageId, reasonCode: gate.reasonCode });
        await this.failExecution(ctx, "POLICY", gate.message);
        return { status: "DENIED", reasonCode: gate.reasonCode };
      }

      const adapter = this.registry.resolve(ctx.adapterSlug);
      if (!adapter || !EXECUTABLE_SLUGS.includes(ctx.adapterSlug as (typeof EXECUTABLE_SLUGS)[number])) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `Adapter ${ctx.adapterSlug} is not executable in this phase`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      // Prompt 8 (§16/§66): a scanner connector executes ONLY against an
      // admin-registered instance resolved for THIS workspace by the
      // store. No instance → NOT_CONFIGURED → TOOL_UNAVAILABLE denial;
      // the DAG degrades the stage instead of inventing scanner output.
      const isConnector = isScannerConnectorAdapter(adapter);
      // Defense in depth (§37/§38): connectors execute ONLY in the
      // passive stage in this phase — never as crawl/vuln-stage tools,
      // and the ACTIVE stage's execution lands behind the approval gate
      // in a later phase.
      if (isConnector && ctx.stageId !== "PASSIVE_SECURITY_ANALYSIS") {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "ADAPTER_DISABLED" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: scanner connectors execute only in PASSIVE_SECURITY_ANALYSIS in this phase`);
        return { status: "DENIED", reasonCode: "ADAPTER_DISABLED" };
      }
      if (isConnector && !ctx.scanner?.instanceId) {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: "TOOL_UNAVAILABLE" });
        await this.failExecution(ctx, "POLICY", `${ctx.adapterSlug}: no scanner instance is configured for this workspace (NOT_CONFIGURED)`);
        return { status: "DENIED", reasonCode: "TOOL_UNAVAILABLE" };
      }
      // Real health (§2/§55): a recon adapter whose binary is absent is
      // denied by policy as TOOL_UNAVAILABLE — never executed, never faked.
      const toolHealthy = await adapter.checkAvailability().catch(() => false);
      const policy = evaluateToolPolicy({
        tool: adapter.metadata, toolEnabled: true, adapterEnabled: true, toolHealthy,
        targetType: ctx.targetType, targetHost: ctx.targetHost, auth: ctx.auth,
        scopeRules: ctx.scopeRules, availableCredentialRefs: [], currentConcurrency: 0, maxConcurrency: 4,
      });
      if (policy.decision !== "ALLOW") {
        await emit("policy.denied", { stageId: ctx.stageId, reasonCode: policy.reasonCode });
        await this.failExecution(ctx, "POLICY", policy.message);
        return { status: "DENIED", reasonCode: policy.reasonCode };
      }

      // Scope matcher double-check for network-capable stages (§12).
      if (ctx.networkCapable && !new ScopeMatcher(ctx.scopeRules).isHostAllowed(ctx.targetHost)) {
        await emit("scope.violation", { stageId: ctx.stageId, reasonCode: "TARGET_OUT_OF_SCOPE" });
        await this.failExecution(ctx, "SCOPE", "Target host is outside the approved scope");
        return { status: "DENIED", reasonCode: "TARGET_OUT_OF_SCOPE" };
      }

      // --- Adapter lifecycle ---
      await this.store.updateExecution(ctx.executionId, { status: "RUNNING", startedAt: new Date() });
      ctx.status = "RUNNING";
      await emit("tool.started", { stageId: ctx.stageId, tool: ctx.adapterSlug });

      const target = { type: ctx.targetType as never, value: ctx.targetValue, host: ctx.targetHost };
      await adapter.validateTarget(target);
      // Adapter config is assembled ONLY from fields the adapter declares
      // (§11): the simulation fixture (mock) and the discovery inputs this
      // stage inherits from earlier stages (Prompt 5 §26).
      const declared = new Set((adapter.metadata.inputSchema ?? []).map((f) => f.name));
      const config: Record<string, unknown> = {};
      // Adapters WITH a declared schema get only declared fields (a recon
      // adapter must never see the simulation knob); schema-less legacy
      // adapters (mock) keep the Phase 4 fixture behaviour.
      if (ctx.simulation?.fixture && (declared.size === 0 || declared.has("fixture"))) config.fixture = "orchestration-e2e";
      if (ctx.stageInputs) {
        if (declared.has("hosts") && ctx.stageInputs.hosts.length > 0) config.hosts = ctx.stageInputs.hosts;
        if (declared.has("urls") && ctx.stageInputs.urls.length > 0) config.urls = ctx.stageInputs.urls;
        if (declared.has("technologies") && (ctx.stageInputs.technologies?.length ?? 0) > 0) config.technologies = ctx.stageInputs.technologies;
        if (declared.has("services") && (ctx.stageInputs.services?.length ?? 0) > 0) config.services = ctx.stageInputs.services;
      }
      // Prompt 7 derived configuration — worker-computed, never client
      // input (§4/§8/§52): Nuclei template approvals follow the PROFILE
      // (WEB_COMPREHENSIVE carries the pre-approved REVIEW_REQUIRED set;
      // baseline runs SAFE only), and rates default to the platform
      // budget's conservative values. The template snapshot chosen here is
      // frozen into the execution metrics below (§6).
      let templateSelection: { snapshot: unknown; selected: string[] } | undefined;
      if (declared.has("approvedTemplateIds")) {
        config.approvedTemplateIds = approvedReviewIdsForProfile(ctx.profile ?? "");
      }
      if (declared.has("requestsPerSecond")) config.requestsPerSecond = 50;
      if (declared.has("concurrency") && ctx.adapterSlug === "nuclei") config.concurrency = 10;
      if (adapter instanceof NucleiAdapter) {
        const sel = adapter.selectionFor(config);
        templateSelection = { snapshot: sel.snapshot, selected: sel.selected.map((t) => t.id) };
      }
      // Prompt 6 derived configuration — computed by the WORKER from the
      // persisted plan/stage, never accepted from clients (§12/§29):
      // wordlist profile follows the assessment profile (never
      // COMPREHENSIVE automatically), and wfuzz's template follows the
      // stage (parameter stage → PARAMETER template, else CONTENT).
      if (declared.has("wordlistProfile")) {
        // Prompt 9 §14/§39: the API baseline also stays SMALL — bigger
        // route lists are never auto-selected for baseline profiles.
        config.wordlistProfile = ctx.profile === "WEB_BASELINE" || ctx.profile === "API_ASSESSMENT" ? "SMALL" : "STANDARD";
      }
      // Prompt 9 derived configuration — worker-computed from the
      // guarded import store, never client input (§15): the schema
      // location Schemathesis tests against and the imported operations
      // its policy filter partitions. allowStateChanging is NEVER set
      // here: the baseline cannot execute state-changing operations.
      if (declared.has("schemaUrl") && (ctx.stageInputs?.specUrls?.length ?? 0) > 0) {
        config.schemaUrl = ctx.stageInputs!.specUrls![0];
      }
      if (declared.has("operations") && (ctx.stageInputs?.operations?.length ?? 0) > 0) {
        config.operations = ctx.stageInputs!.operations;
      }
      if (declared.has("template")) {
        config.template = ctx.stageId === "PARAMETER_DISCOVERY" ? "PARAMETER" : "CONTENT";
      }
      // Prompt 8 derived configuration — trusted worker state only (§6/
      // §16): the workspace's registered scanner instance + session
      // profile binding (store-resolved), tenancy ids for context
      // isolation, and the persisted scope snapshot the connector checks
      // its context against. Clients can supply none of this.
      if (isConnector) {
        if (declared.has("instanceId") && ctx.scanner?.instanceId) config.instanceId = ctx.scanner.instanceId;
        if (declared.has("sessionProfileId") && ctx.scanner?.sessionProfileId) config.sessionProfileId = ctx.scanner.sessionProfileId;
        if (declared.has("workspaceId")) config.workspaceId = ctx.workspaceId;
        if (declared.has("assessmentId") && ctx.assessmentId) config.assessmentId = ctx.assessmentId;
        if (declared.has("scanId")) config.scanId = ctx.scanId;
        if (declared.has("scopeIncludeHosts")) config.scopeIncludeHosts = ctx.scopeRules.includeHosts;
        if (declared.has("scopeExcludeHosts")) config.scopeExcludeHosts = ctx.scopeRules.excludeHosts;
        if (declared.has("scopeAllowedPorts")) config.scopeAllowedPorts = ctx.scopeRules.allowedPorts;
        if (declared.has("scopeAllowedPaths")) config.scopeAllowedPaths = ctx.scopeRules.allowedPaths;
        if (declared.has("scopeExcludedPaths")) config.scopeExcludedPaths = ctx.scopeRules.excludedPaths;
        await emit("passive_analysis.started", { stageId: ctx.stageId, tool: ctx.adapterSlug, instanceId: ctx.scanner?.instanceId ?? null });
      }
      const plan = await adapter.buildExecutionPlan(target, config);

      const timeoutMs = ctx.simulation?.failWith === "TIMEOUT"
        ? Math.min(50, ctx.timeoutSeconds * 1000)
        : ctx.timeoutSeconds * 1000;
      let rawOutput: string | undefined;
      await this.runWithTimeoutAndCancellation(ctx, async () => {
        if (ctx.simulation?.failWith === "TOOL_ERROR") throw new Error("deterministic mock tool failure");
        if (ctx.simulation?.failWith === "TIMEOUT") await sleep(1_000); // overruns the clamped test timeout (§58)
        if (ctx.simulation?.delayMs) {
          // Chunked cooperative delay: cancellation is observed within ~25ms
          // instead of after the whole simulated duration (§26).
          let remaining = ctx.simulation.delayMs;
          while (remaining > 0) {
            await sleep(Math.min(25, remaining));
            remaining -= 25;
            if (await this.store.isCancelled(ctx.scanId)) return;
          }
        }
        const execResult = await adapter.execute(plan);
        rawOutput = execResult.rawOutput;
      }, timeoutMs);

      if (await this.store.isCancelled(ctx.scanId)) {
        await this.store.updateExecution(ctx.executionId, { status: "CANCELLED", completedAt: new Date() });
        await emit("tool.failed", { stageId: ctx.stageId, reasonCode: "CANCELLED" });
        return { status: "CANCELLED" };
      }

      await this.transition(ctx, "PARSING");
      const parsed = await adapter.parse(rawOutput ?? "");
      // Raw tool output is preserved as the execution artifact (§31/§35),
      // named for the tool + format — never the normalized form.
      const ext = plan.expectedOutputFormat === "JSONL" ? "jsonl" : plan.expectedOutputFormat === "JSON" ? "json" : "txt";
      const raw = rawOutput ?? JSON.stringify(parsed);
      const artifact = await this.objectStore.put(
        rawArtifactKey(ctx.scanId, ctx.executionId, `${ctx.adapterSlug}.${ext}`),
        raw,
        plan.expectedOutputFormat === "TEXT" ? "text/plain" : "application/json",
      );
      await this.transition(ctx, "NORMALIZING");
      const normalized = await adapter.normalize(parsed);
      const processed = processNormalizedResult(normalized, { scopeRules: ctx.scopeRules, toolExecutionId: ctx.executionId, toolSlug: ctx.adapterSlug, artifactKey: artifact.storageKey });
      const counts = await this.store.persistResult(ctx.scanId, ctx.executionId, processed);
      // Prompt 8 connector lifecycle events (§72): ids + counts only —
      // never secrets, never traffic (§20).
      if (isConnector) {
        await emit("scanner.context_created", { stageId: ctx.stageId, tool: ctx.adapterSlug, instanceId: ctx.scanner?.instanceId ?? null });
        if (normalized.metrics.sessionExpired === 1) {
          await emit("auth_session.expired", { stageId: ctx.stageId, tool: ctx.adapterSlug });
        }
        await emit("passive_analysis.completed", {
          stageId: ctx.stageId, tool: ctx.adapterSlug,
          transactions: counts.transactions ?? processed.transactions.length,
          issues: normalized.metrics.passiveIssues ?? processed.findings.length,
          endpointsImported: normalized.metrics.endpointsImported ?? processed.endpoints.length,
        });
        await emit("scanner.context_destroyed", { stageId: ctx.stageId, tool: ctx.adapterSlug });
      }
      // §59: aggregated recon events, never one record per discovered URL.
      for (const a of processed.assets) {
        if (a.scopeStatus === "IN_SCOPE") await emit("asset.discovered", { stageId: ctx.stageId, host: a.host, tool: ctx.adapterSlug });
        else await emit("asset.out_of_scope", { stageId: ctx.stageId, host: a.host, tool: ctx.adapterSlug });
      }
      if (processed.endpoints.length > 0) await emit("endpoint.discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.endpoints.length });
      // Prompt 9 §78: API inventory/test events — counts and verdicts
      // only, never payloads, tokens or traffic.
      if (processed.apiServices.length > 0) {
        await emit("api.service_discovered", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.apiServices.length });
      }
      if (processed.graphqlServices.length > 0) {
        await emit("graphql.schema_imported", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: processed.graphqlServices.length });
      }
      if (processed.jwtProfiles.length > 0) {
        await emit("jwt.analyzed", { stageId: ctx.stageId, tool: ctx.adapterSlug, tokens: processed.jwtProfiles.length });
      }
      if (typeof normalized.metrics.blockedOperations === "number" && normalized.metrics.blockedOperations > 0) {
        await emit("api.operation_blocked", { stageId: ctx.stageId, tool: ctx.adapterSlug, count: normalized.metrics.blockedOperations });
      }
      for (const f of processed.findings) await emit("finding.created", { stageId: ctx.stageId, isMock: f.isMock, severity: f.severity });

      await this.store.updateExecution(ctx.executionId, {
        status: "COMPLETED", completedAt: new Date(), exitCode: 0,
        outputLocation: artifact.storageKey,
        metrics: {
          checksum: artifact.checksum, size: artifact.size,
          assets: counts.assets, findings: counts.findings,
          endpoints: counts.endpoints ?? processed.endpoints.length,
          services: counts.services ?? processed.services.length,
          technologies: counts.technologies ?? processed.technologies.length,
          parameters: counts.parameters ?? processed.parameters.length,
          forms: counts.forms ?? processed.forms.length,
          transactions: counts.transactions ?? processed.transactions.length,
          webSockets: counts.webSockets ?? processed.webSockets.length,
          suppressedEndpoints: processed.suppressedEndpoints,
          ...(templateSelection ? { templateSnapshot: templateSelection.snapshot, templatesSelected: templateSelection.selected } : {}),
          ...normalized.metrics,
        },
      });
      await emit("tool.completed", { stageId: ctx.stageId, tool: ctx.adapterSlug, assets: counts.assets, findings: counts.findings });
      return { status: "COMPLETED", assets: counts.assets, findings: counts.findings };
    } catch (error) {
      const category = classifyError(error);
      if (category === "TIMEOUT") {
        await this.store.updateExecution(ctx.executionId, { status: "TIMED_OUT", completedAt: new Date(), error: "Execution timed out" });
        await emit("tool.failed", { stageId: ctx.stageId, reasonCode: "TIMED_OUT" });
        return { status: "TIMED_OUT", category };
      }
      await this.failExecution(ctx, category, error instanceof Error ? error.message : "unknown error");
      await this.store.recordDeadLetter({
        jobId: idempotencyKey(ctx.scanId, ctx.stageId, ctx.attempt), queue: "stage-execution",
        scanId: ctx.scanId, stageId: ctx.stageId, executionId: ctx.executionId,
        errorCategory: category, errorMessage: error instanceof Error ? error.message : "unknown", attempts: ctx.attempt,
      });
      return { status: "FAILED", category };
    }
  }

  /** Availability probe used by the DAG runner to degrade gracefully when
   *  one adapter of a multi-adapter stage is unavailable (§56). */
  async isExecutable(slug: string): Promise<boolean> {
    if (!EXECUTABLE_SLUGS.includes(slug as (typeof EXECUTABLE_SLUGS)[number])) return false;
    const adapter = this.registry.resolve(slug);
    if (!adapter) return false;
    return adapter.checkAvailability().catch(() => false);
  }

  private async transition(ctx: ExecutionContextRecord, to: string): Promise<void> {
    assertExecutionTransition(ctx.status as never, to as never);
    await this.store.updateExecution(ctx.executionId, { status: to });
    ctx.status = to;
  }

  private async failExecution(ctx: ExecutionContextRecord, category: string, message: string): Promise<void> {
    await this.store.updateExecution(ctx.executionId, { status: "FAILED", completedAt: new Date(), error: message });
    await this.store.recordEvent(makeEvent(ctx.scanId, ctx.workspaceId, "tool.failed", { stageId: ctx.stageId, reasonCode: category }));
  }

  /** Cooperative cancellation + hard timeout (§26/§28): the work races a
   *  timer, and cancellation is polled so a delayed mock stops promptly. */
  private async runWithTimeoutAndCancellation(ctx: ExecutionContextRecord, work: () => Promise<void>, timeoutMs: number): Promise<void> {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error("Execution timed out"), { name: "ExecutionTimeoutError" })), timeoutMs);
    });
    void ctx;
    try {
      await Promise.race([work(), timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
