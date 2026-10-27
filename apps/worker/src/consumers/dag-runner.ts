import {
  buildDag, dependentOutcomeOnFailure, evaluateAuthorizationGate, finalScanStatus,
  makeEvent, monotonicProgress, progressForPlan, readyStages, type GateInput,
  type ScanPlan, type ScanEventRecord,
} from "@zerosweep/orchestration";
import type { StageExecutor, StageJobData, ExecutionStore, StageExecutionOutcome } from "../executors/stage-executor";

/**
 * DAG runner (Prompt 4 §5, §20, §56): drives a persisted ScanPlan to
 * completion. Ready stages are computed from the DAG on every iteration —
 * never a hardcoded sequence. Tool stages dispatch stage-execution jobs (IDs
 * only); platform stages (authorization, scope, normalization, correlation,
 * risk, report preparation) execute as engine checks in-process. Pause stops
 * scheduling; cancellation stops everything and converges the scan to
 * CANCELLED; a stage failure is resolved through its failure strategy.
 */

export interface ScanRunRecord {
  plan: ScanPlan;
  scanStatus: string;
  progress: number;
  gate: GateInput;
}

export interface ScanRunStore extends ExecutionStore {
  loadScanRun(scanId: string): Promise<ScanRunRecord | null>;
  stageStatuses(scanId: string): Promise<Map<string, string>>;
  updateScan(scanId: string, patch: Record<string, unknown>): Promise<void>;
  updateStage(scanId: string, stageType: string, patch: Record<string, unknown>): Promise<void>;
  ensureExecution(scanId: string, stageType: string, adapterSlug: string, attempt: number): Promise<{ id: string; status: string }>;
  markReportPending(scanId: string): Promise<void>;
  isPaused(scanId: string): Promise<boolean>;
  /** Prompt 7 platform-stage data hooks (optional: stores that do not
   *  implement them leave those stages as deterministic completions —
   *  the production and fake stores both implement them). */
  summarizeFindings?(scanId: string): Promise<Record<string, unknown> | null>;
  correlateScanFindings?(scanId: string): Promise<{ canonical: number; duplicates: number; stats: Record<string, unknown> } | null>;
  recalculateFindingRisk?(scanId: string): Promise<{ updated: number } | null>;
  /** Prompt 9 platform-stage hooks (same optional pattern): each returns
   *  a counts-only summary the runner emits as the stage's API event, or
   *  null when there is nothing to report. */
  consolidateApiServices?(scanId: string): Promise<{ services: number; endpoints: number } | null>;
  summarizeApiSpecifications?(scanId: string): Promise<{ specifications: number; operations: number } | null>;
  mapApiAuthentication?(scanId: string): Promise<{ contexts: number; servicesWithAuth: number } | null>;
  analyzeJwtProfiles?(scanId: string): Promise<{ tokens: number; findings: number } | null>;
  inventoryWebSockets?(scanId: string): Promise<{ webSockets: number; authenticated: number } | null>;
  /** Prompt 10 platform-stage hook (same optional pattern): expand the
   *  network target into bounded chunks (§5/§62) and persist them for
   *  checkpointing. Returns counts only — hosts are never materialized
   *  beyond the bounded cap. */
  expandNetworkTargets?(scanId: string): Promise<{ mode: string; hosts: number; chunks: number; totalHosts: number } | null>;
  /** Prompt 12 platform-stage hooks (same optional pattern): snapshot
   *  acquisition, language detection, dependency inventory, SBOM
   *  generation and the quality gate — engine work over the snapshot,
   *  counts/verdicts only in events (never secret values, §110). */
  acquireSourceSnapshot?(scanId: string): Promise<{ snapshotHash: string; files: number; sourceKind: string } | null>;
  detectSourceLanguages?(scanId: string): Promise<{ languages: number; primaryLanguage?: string; frameworks: number; buildSystems: number } | null>;
  inventorySourceDependencies?(scanId: string): Promise<{ components: number; manifests: number } | null>;
  generateSourceSbom?(scanId: string): Promise<{ format: string; checksum: string; components: number } | null>;
  evaluateSourceQualityGate?(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null>;
  /** Prompt 13 platform-stage hooks (same optional pattern): image
   *  resolution (tag → digest + drift snapshot, §5/§78) and the
   *  container quality gate (§75). skipped=true means the scan carries
   *  no image context (e.g. a cluster-targeted CLOUD_NATIVE_FULL scan)
   *  and the stage completes without work; null means an image scan
   *  whose image cannot be resolved — an honest failure. */
  resolveContainerImage?(scanId: string): Promise<{ imageRef: string; digest?: string; drift?: boolean; skipped?: boolean } | null>;
  evaluateContainerQualityGate?(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null>;
  /** Prompt 14 platform-stage hooks (same optional pattern): cloud
   *  account authorization (§9 — null fails the scan honestly as
   *  NOT_CONFIGURED), section analysis over persisted inventory
   *  (§36–§57), compliance/drift/risk-path assessment (§63–§68) and
   *  the cloud quality gate (§70). */
  validateCloudAccount?(scanId: string): Promise<{ status: string; provider?: string } | null>;
  analyzeCloudSection?(scanId: string, section: string): Promise<{ findings: number; assessments: number } | null>;
  assessCloudCompliance?(scanId: string): Promise<{ assessed: number; failed: number; drift: number; riskPaths: number } | null>;
  evaluateCloudQualityGate?(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null>;
  /** Prompt 14: the provider of the scan's registered cloud account —
   *  the CLOUD_INVENTORY stage narrows its connector candidates to it. */
  cloudScanProvider?(scanId: string): Promise<string | null>;
  /** Prompt 15 platform-stage hooks (same optional pattern): domain
   *  authorization (§9/§12 — null fails the scan honestly as
   *  NOT_CONFIGURED), LDAP posture analysis over persisted inventory
   *  (§70/§71), identity-graph construction (§32/§65) and defensive
   *  attack-path modeling (§34–§37). */
  validateDirectoryDomain?(scanId: string): Promise<{ status: string; domainRef?: string } | null>;
  analyzeDirectoryLdapPosture?(scanId: string): Promise<{ findings: number; assessments: number } | null>;
  buildDirectoryGraph?(scanId: string): Promise<{ nodes: number; edges: number; privileged: number; drift: number } | null>;
  analyzeAttackPaths?(scanId: string): Promise<{ paths: number; findings: number } | null>;
  /** Prompt 17 platform-stage hooks (same optional pattern): build
   *  validation (§5/§6 — null fails the scan honestly as
   *  NOT_CONFIGURED), metadata extraction over the build's registered
   *  artifacts (§6/§20 — secret scan + SCA + SBOM inputs), manifest /
   *  plist posture analysis (§20–§41) and the mobile quality gate
   *  (§90). */
  validateMobileBuild?(scanId: string): Promise<{ buildHash: string; platform: string; artifactFormat: string } | null>;
  extractMobileMetadata?(scanId: string): Promise<{ permissions: number; components: number; endpoints: number; secrets: number; componentsScanned: number } | null>;
  analyzeMobileManifest?(scanId: string): Promise<{ findings: number; assessments: number } | null>;
  evaluateMobileQualityGate?(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null>;
  /** Prompt 18 platform-stage hooks (same optional pattern): artifact
   *  validation (§3/§6 — null fails the scan honestly as
   *  NOT_CONFIGURED), metadata extraction over the registered
   *  artifact (§12–§50), the dependency/SBOM stages for binary
   *  profiles, the governed debug-session stage (§64–§74) and the
   *  binary quality gate. */
  validateBinaryArtifact?(scanId: string): Promise<{ artifactHash: string; format: string } | null>;
  extractBinaryMetadata?(scanId: string): Promise<{ sections: number; functions: number; dependencies: number; secrets: number; componentsScanned: number } | null>;
  inventoryBinaryDependencies?(scanId: string): Promise<{ components: number } | null>;
  generateBinarySbom?(scanId: string): Promise<{ format: string; checksum: string; components: number } | null>;
  evaluateBinaryDebugSession?(scanId: string): Promise<{ status: string; reason?: string } | null>;
  evaluateBinaryQualityGate?(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null>;
  /** Prompt 19 platform-stage hooks (same optional pattern):
   *  environment validation (§3/§4 — null fails the scan honestly as
   *  NOT_CONFIGURED), posture analysis over persisted inventory
   *  (§32–§60: encryption, rogue, drift, events) and the wireless
   *  quality gate (§60). */
  validateWirelessEnvironment?(scanId: string): Promise<{ environmentId: string; environmentRef?: string } | null>;
  analyzeWirelessPosture?(scanId: string): Promise<{ findings: number; events: number; drift: number; accessPoints: number } | null>;
  evaluateWirelessQualityGate?(scanId: string): Promise<{ status: string; failedRules: number; warningRules: number } | null>;
}

export type StageDispatcher = (job: StageJobData) => Promise<StageExecutionOutcome>;

const TERMINAL = new Set(["COMPLETED", "PARTIAL", "FAILED", "SKIPPED", "CANCELLED"]);

/**
 * Finding-pipeline stages that must read SKIPPED (not a vacuous COMPLETED)
 * when no tool produced any output: NORMALIZATION, CORRELATION and
 * RISK_ANALYSIS only process what tools found. REPORT_GENERATION is exempt
 * (it documents the outcome, failures included), as are gate stages.
 * PARTIAL_DATA counts as output; Continue-PARTIAL (zero tools completed)
 * does not. Pure-platform scans (no tool stage seen) are unaffected.
 */
export const NO_INPUT_SKIP_STAGES = ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS"] as const;
export function shouldSkipNoInputStage(stageId: string, toolStagesSeen: number, toolOutput: boolean): boolean {
  return (NO_INPUT_SKIP_STAGES as readonly string[]).includes(stageId) && toolStagesSeen > 0 && !toolOutput;
}

export class DagRunner {
  constructor(
    private readonly store: ScanRunStore,
    private readonly executor: StageExecutor,
    /** Availability probe (defaults to the executor's): lets a multi-adapter
     *  stage skip an unavailable adapter instead of failing (§56). */
    private readonly isAdapterAvailable: (slug: string) => Promise<boolean> = (slug) => executor.isExecutable(slug),
  ) {}

  /** Default dispatcher: run the stage job inline (single-worker/dev). The
   *  BullMQ dispatcher in index.ts enqueues the same job shape instead. */
  private readonly directDispatch: StageDispatcher = (job) => this.executor.run(job);

  async run(scanId: string, dispatch: StageDispatcher = this.directDispatch): Promise<{ status: string }> {
    const run = await this.store.loadScanRun(scanId);
    if (!run) return { status: "NOT_FOUND" };
    const { plan } = run;
    const emit = (type: ScanEventRecord["type"], payload: ScanEventRecord["payload"]) =>
      this.store.recordEvent(makeEvent(scanId, plan.workspaceId, type, payload));

    const defs = plan.stages.map((s) => ({
      type: s.type, name: s.name, description: s.description,
      requiredCapabilities: s.requiredCapabilities as never[], dependencies: s.dependencies,
      weight: s.weight, timeoutSeconds: s.timeoutSeconds,
      failureStrategy: s.failureStrategy as never, networkCapable: s.networkCapable,
    }));
    const { dag, errors } = buildDag(defs as never);
    if (!dag) {
      await this.store.updateScan(scanId, { status: "FAILED", errorSummary: `Invalid plan: ${errors.map((e) => e.message).join("; ")}`, completedAt: new Date() });
      await emit("scan.failed", { reason: "INVALID_PLAN" });
      return { status: "FAILED" };
    }

    if (run.scanStatus === "CREATED" || run.scanStatus === "QUEUED") {
      await this.store.updateScan(scanId, { status: "PREPARING" });
    }
    await emit("scan.started", { profile: plan.profile });
    await this.store.updateScan(scanId, { status: "RUNNING", startedAt: new Date() });

    let lastProgress = run.progress;
    // Honest pipeline stages (§8): finding-pipeline stages (normalize /
    // correlate / risk) only mean something when a tool actually produced
    // output. If every tool stage so far failed outright (Continue-PARTIAL
    // included — it means zero tools completed), these stages have nothing
    // to process and must read SKIPPED, never a vacuous COMPLETED.
    // REPORT_GENERATION is exempt: it documents the outcome, failures
    // included. Tracked loop-locally: PARTIAL_DATA counts as output
    // (at least one tool completed); Continue-PARTIAL does not.
    let toolOutput = false;
    let toolStagesSeen = 0;
    const maxIterations = plan.stages.length * 4 + 16;

    for (let i = 0; i < maxIterations; i++) {
      const statuses = await this.store.stageStatuses(scanId);
      const current = await this.store.loadScanRun(scanId);
      if (!current || current.scanStatus === "CANCELLED") {
        await this.cancelRemaining(scanId, plan, statuses);
        await emit("scan.cancelled", {});
        return { status: "CANCELLED" };
      }
      if (await this.store.isPaused(scanId)) {
        await emit("scan.paused", {});
        return { status: "PAUSED" };
      }

      const ready = readyStages(dag, statuses);
      if (ready.length === 0) {
        if ([...statuses.values()].every((s) => TERMINAL.has(s))) break;
        // Nothing ready and nothing terminal-blocked can progress: a failed
        // dependency with a continue strategy is normalized to PARTIAL above,
        // so reaching here means the plan is wedged — fail honestly.
        await this.store.updateScan(scanId, { status: "FAILED", errorSummary: "Pipeline wedged: no stage can proceed", completedAt: new Date() });
        await emit("scan.failed", { reason: "PIPELINE_WEDGED" });
        return { status: "FAILED" };
      }

      for (const node of ready) {
        const planned = plan.stages.find((s) => s.id === node.id)!;
        await this.store.updateStage(scanId, node.id, { status: "RUNNING", startedAt: new Date() });
        await emit("stage.started", { stageId: node.id });

        if (planned.selectedAdapters.length === 0) {
          // No tool produced anything yet, but tool stages already ran and
          // all failed: the finding pipeline has no input. Skip honestly
          // instead of completing over zero findings (the "all stages
          // worked" bug). Gate stages and REPORT_GENERATION are exempt.
          if (shouldSkipNoInputStage(node.id, toolStagesSeen, toolOutput)) {
            await this.store.updateStage(scanId, node.id, { status: "SKIPPED", progress: 100, completedAt: new Date() });
            await emit("stage.skipped", { stageId: node.id, because: "no tool produced output" });
            continue;
          }
          const outcome = await this.runPlatformStage(scanId, run, node.id, emit);
          await this.store.updateStage(scanId, node.id, { status: outcome, progress: 100, completedAt: new Date() });
          await emit(outcome === "FAILED" ? "stage.failed" : "stage.completed", { stageId: node.id });
          if (outcome === "FAILED") {
            await this.skipRemaining(scanId, plan, await this.store.stageStatuses(scanId));
            await this.store.updateScan(scanId, { status: "FAILED", completedAt: new Date() });
            await emit("scan.failed", { stageId: node.id, reason: "GATE_DENIED" });
            return { status: "FAILED" };
          }
          if (node.id === "REPORT_GENERATION") await this.store.markReportPending(scanId);
          continue;
        }

        // Prompt 5 §16: a stage may select SEVERAL adapters (e.g. four
        // subdomain sources in PASSIVE_RECON). All of them run; an
        // unavailable one is skipped when siblings can still deliver
        // (§56 — capability degraded, orchestration never crashes), and the
        // stage outcome aggregates: all complete → COMPLETED, some →
        // PARTIAL (§55), none → the failure-strategy path below.
        let candidates = planned.selectedAdapters;
        // Prompt 14 §16–§18: the CLOUD_INVENTORY stage selects every
        // provider connector at plan time; execution narrows to the
        // connector of the account's OWN provider (store-resolved) —
        // the other providers' connectors never run against it.
        if (node.id === "CLOUD_INVENTORY" && this.store.cloudScanProvider) {
          const provider = await this.store.cloudScanProvider(scanId);
          if (provider) {
            const own = `${provider.toLowerCase()}-inventory`;
            const narrowed = candidates.filter((a) => a.slug === own || a.slug === "roadtools");
            if (narrowed.length > 0) candidates = narrowed;
          }
        }
        if (candidates.length > 1) {
          const availability = await Promise.all(candidates.map(async (a) => ({ slug: a.slug, ok: await this.isAdapterAvailable(a.slug).catch(() => false) })));
          const available = availability.filter((a) => a.ok);
          for (const skipped of availability.filter((a) => !a.ok)) {
            await emit("tool.failed", { stageId: node.id, tool: skipped.slug, reasonCode: "TOOL_UNAVAILABLE", degraded: true });
          }
          if (available.length > 0) candidates = candidates.filter((a) => available.some((x) => x.slug === a.slug));
        }
        const executions = await Promise.all(candidates.map(async (a) => ({
          slug: a.slug,
          exec: await this.store.ensureExecution(scanId, node.id, a.slug, 1),
        })));
        const outcomes = await Promise.all(executions.map(({ exec }) =>
          dispatch({ kind: "STAGE_EXECUTION", scanId, stageId: node.id, toolExecutionId: exec.id, attempt: 1 })));
        const outcome: StageExecutionOutcome = outcomes.length === 1
          ? outcomes[0]!
          : outcomes.some((o) => o.status === "CANCELLED")
            ? { status: "CANCELLED" }
            : outcomes.every((o) => o.status === "COMPLETED" || o.status === "ALREADY_COMPLETED")
              ? { status: "COMPLETED", assets: 0, findings: 0 }
              : outcomes.some((o) => o.status === "COMPLETED" || o.status === "ALREADY_COMPLETED")
                ? { status: "PARTIAL_DATA" }
                : outcomes[0]!;

        // Track tool output for the honest-pipeline rule above. A single
        // tool stage with zero executions never reaches this branch (it is
        // a platform stage), so every outcome here came from real tools.
        toolStagesSeen += 1;
        if (outcome.status === "COMPLETED" || outcome.status === "ALREADY_COMPLETED" || outcome.status === "PARTIAL_DATA") {
          toolOutput = true;
        }

        if (outcome.status === "COMPLETED" || outcome.status === "ALREADY_COMPLETED") {
          await this.store.updateStage(scanId, node.id, { status: "COMPLETED", progress: 100, completedAt: new Date() });
          await emit("stage.completed", { stageId: node.id });
        } else if (outcome.status === "PARTIAL_DATA") {
          await this.store.updateStage(scanId, node.id, { status: "PARTIAL", progress: 100, completedAt: new Date() });
          await emit("stage.failed", { stageId: node.id, continued: true, partialAdapters: true });
        } else if (outcome.status === "CANCELLED") {
          await this.store.updateStage(scanId, node.id, { status: "CANCELLED", completedAt: new Date() });
          await this.cancelRemaining(scanId, plan, await this.store.stageStatuses(scanId));
          await emit("scan.cancelled", { stageId: node.id });
          return { status: "CANCELLED" };
        } else {
          // Failure: resolve through the stage's failure strategy (§8).
          const onFailure = dependentOutcomeOnFailure(planned.failureStrategy as never);
          if (onFailure === "FAIL_SCAN") {
            await this.store.updateStage(scanId, node.id, { status: "FAILED", completedAt: new Date() });
            await emit("stage.failed", { stageId: node.id });
            await this.skipRemaining(scanId, plan, await this.store.stageStatuses(scanId));
            await this.store.updateScan(scanId, { status: "FAILED", completedAt: new Date() });
            await emit("scan.failed", { stageId: node.id, reason: outcome.status });
            return { status: "FAILED" };
          }
          if (onFailure === "SKIP") {
            await this.store.updateStage(scanId, node.id, { status: "FAILED", completedAt: new Date() });
            await emit("stage.failed", { stageId: node.id });
            await this.skipDependents(scanId, plan, node.id, await this.store.stageStatuses(scanId), emit);
          } else {
            // Continue strategies: stage is PARTIAL — dependents may proceed.
            await this.store.updateStage(scanId, node.id, { status: "PARTIAL", progress: 100, completedAt: new Date() });
            await emit("stage.failed", { stageId: node.id, continued: true });
          }
        }

        const after = await this.store.stageStatuses(scanId);
        const next = monotonicProgress(lastProgress, progressForPlan(plan.stages, after));
        if (next !== lastProgress) {
          lastProgress = next;
          await this.store.updateScan(scanId, { progress: next, currentStage: node.id });
          await emit("scan.progress", { progress: next, stageId: node.id });
        }
      }
    }

    const statuses = await this.store.stageStatuses(scanId);
    const finalStatus = finalScanStatus(statuses.values());
    await this.store.updateScan(scanId, { status: finalStatus, progress: 100, completedAt: new Date() });
    await emit(finalStatus === "COMPLETED" ? "scan.completed" : "scan.failed", { finalStatus });
    if (plan.stages.some((s) => s.type === "SOURCE_ACQUISITION")) {
      await emit("source.scan_completed", { finalStatus });
    }
    if (plan.stages.some((s) => s.type === "IMAGE_RESOLUTION" || s.type === "CLUSTER_INVENTORY" || s.type === "DOCKER_POSTURE")) {
      await emit("container.scan_completed", { finalStatus });
    }
    if (plan.stages.some((s) => s.type === "CLOUD_AUTH")) {
      await emit("cloud.scan_completed", { finalStatus });
    }
    if (plan.stages.some((s) => s.type === "DOMAIN_DISCOVERY")) {
      await emit("ad.scan_completed", { finalStatus });
    }
    if (plan.stages.some((s) => s.type === "MOBILE_ARTIFACT_INTAKE")) {
      await emit("mobile.scan_completed", { finalStatus });
    }
    if (plan.stages.some((s) => s.type === "BINARY_ARTIFACT_INTAKE")) {
      await emit("binary.scan_completed", { finalStatus });
    }
    if (plan.stages.some((s) => s.type === "WIRELESS_CAPTURE_INTAKE")) {
      await emit("wireless.scan_completed", { finalStatus });
    }
    return { status: finalStatus };
  }

  /** Platform stages run engine checks, not tools. Authorization/scope stages
   *  evaluate the full gate; pipeline-internal stages complete deterministically. */
  private async runPlatformStage(
    scanId: string,
    run: ScanRunRecord,
    stageId: string,
    emit: (type: ScanEventRecord["type"], payload: ScanEventRecord["payload"]) => Promise<void>,
  ): Promise<"COMPLETED" | "FAILED"> {
    if (stageId === "AUTHORIZATION_CHECK" || stageId === "SCOPE_VALIDATION") {
      const gate = evaluateAuthorizationGate(run.gate);
      if (!gate.allowed) {
        await emit(gate.reasonCode === "TARGET_OUT_OF_SCOPE" ? "scope.violation" : "policy.denied", { stageId, reasonCode: gate.reasonCode });
        return "FAILED";
      }
    }
    // Prompt 8 §37/§66: the passive stage reached the platform path
    // because NO connector was selected (none configured/healthy for this
    // workspace). It completes honestly as SKIPPED — never simulated.
    if (stageId === "PASSIVE_SECURITY_ANALYSIS") {
      await emit("passive_analysis.skipped", { stageId, reasonCode: "NO_CONNECTOR_CONFIGURED" });
      return "COMPLETED";
    }
    // Prompt 8 §38/§57: an active stage with no adapters selected means
    // active scanning was not requested/approved for this scan — recorded
    // as a denial event, and the scan proceeds (active scanning is an
    // opt-in extra, never a pipeline requirement).
    if (stageId === "ACTIVE_SECURITY_ANALYSIS") {
      await emit("active_scan.denied", { stageId, reasonCode: "ACTIVE_SCAN_NOT_REQUESTED" });
      return "COMPLETED";
    }
    // Prompt 7 §14: the finding pipeline stages do real deterministic work
    // over persisted findings when the store supports it.
    if (stageId === "NORMALIZATION" && this.store.summarizeFindings) {
      const summary = await this.store.summarizeFindings(scanId);
      if (summary) await emit("finding.normalized", { stageId, ...summary });
    }
    if (stageId === "CORRELATION" && this.store.correlateScanFindings) {
      const result = await this.store.correlateScanFindings(scanId);
      if (result && result.duplicates > 0) {
        await emit("finding.correlated", { stageId, canonical: result.canonical, duplicatesMerged: result.duplicates });
      }
    }
    if (stageId === "RISK_ANALYSIS" && this.store.recalculateFindingRisk) {
      const result = await this.store.recalculateFindingRisk(scanId);
      if (result) await emit("risk.calculated", { stageId, updated: result.updated });
    }
    // Prompt 9 platform stages (§39/§43): deterministic inventory work
    // over persisted state — imported specifications, captured traffic
    // metadata, registered auth contexts and JWT inspection. None of
    // them generates traffic or executes an operation.
    if (stageId === "API_DISCOVERY" && this.store.consolidateApiServices) {
      const result = await this.store.consolidateApiServices(scanId);
      if (result) await emit("api.service_discovered", { stageId, services: result.services, endpoints: result.endpoints });
    }
    if (stageId === "SPEC_IMPORT" && this.store.summarizeApiSpecifications) {
      const result = await this.store.summarizeApiSpecifications(scanId);
      if (result) await emit("api.spec_imported", { stageId, specifications: result.specifications, operations: result.operations });
    }
    if (stageId === "AUTH_MAPPING" && this.store.mapApiAuthentication) {
      const result = await this.store.mapApiAuthentication(scanId);
      if (result) await emit("api.auth_mapped", { stageId, contexts: result.contexts, servicesWithAuth: result.servicesWithAuth });
    }
    if (stageId === "JWT_ANALYSIS" && this.store.analyzeJwtProfiles) {
      const result = await this.store.analyzeJwtProfiles(scanId);
      if (result) await emit("jwt.analyzed", { stageId, tokens: result.tokens, findings: result.findings });
    }
    if (stageId === "WEBSOCKET_INVENTORY" && this.store.inventoryWebSockets) {
      const result = await this.store.inventoryWebSockets(scanId);
      if (result) await emit("websocket.inventoried", { stageId, webSockets: result.webSockets, authenticated: result.authenticated });
    }
    if (stageId === "API_FINDING_NORMALIZATION" && this.store.summarizeFindings) {
      const summary = await this.store.summarizeFindings(scanId);
      const total = typeof summary?.totalFindings === "number" ? summary.totalFindings : 0;
      await emit("api.test_completed", { stageId, totalFindings: total });
    }
    // Prompt 10 §5/§25/§62: target expansion is engine work — the store
    // canonicalizes the CIDR target, applies the size policy and writes
    // bounded chunk rows; the runner only records the counts.
    if (stageId === "TARGET_EXPANSION" && this.store.expandNetworkTargets) {
      const result = await this.store.expandNetworkTargets(scanId);
      if (result) {
        if (result.mode === "DENIED") {
          await emit("network.protected_target_blocked", { stageId, reasonCode: "CIDR_SIZE_DENIED", totalHosts: result.totalHosts });
        } else {
          await emit("network.targets_expanded", { stageId, mode: result.mode, hosts: result.hosts, chunks: result.chunks, totalHosts: result.totalHosts });
        }
      }
    }
    // Prompt 12 platform stages (§19/§96): snapshot acquisition →
    // language detection → dependency inventory → SBOM → quality gate.
    // The store hooks do the deterministic work; events carry counts and
    // verdicts only.
    if (stageId === "SOURCE_ACQUISITION") {
      if (!this.store.acquireSourceSnapshot) return "FAILED";
      const result = await this.store.acquireSourceSnapshot(scanId);
      if (!result) {
        // No acquirable snapshot exists for this scan (e.g. a git
        // repository whose clone has not been provisioned): the scan
        // cannot proceed honestly — acquisition is a FAIL_SCAN stage.
        await emit("policy.denied", { stageId, reasonCode: "SOURCE_SNAPSHOT_UNAVAILABLE" });
        return "FAILED";
      }
      await emit("source.snapshot_created", { stageId, snapshotHash: result.snapshotHash, files: result.files, sourceKind: result.sourceKind });
    }
    if (stageId === "LANGUAGE_DETECTION" && this.store.detectSourceLanguages) {
      const result = await this.store.detectSourceLanguages(scanId);
      if (result) await emit("source.languages_detected", { stageId, languages: result.languages, primaryLanguage: result.primaryLanguage ?? null, frameworks: result.frameworks, buildSystems: result.buildSystems });
    }
    if (stageId === "DEPENDENCY_INVENTORY" && this.store.inventoryBinaryDependencies) {
      // Prompt 18: binary profiles reuse the dependency stage — the
      // binary hook answers for binary scans, the source hook below
      // for source scans; each returns null outside its family.
      const result = await this.store.inventoryBinaryDependencies(scanId);
      if (result) await emit("binary.dependencies_inventoried", { stageId, components: result.components });
    }
    if (stageId === "DEPENDENCY_INVENTORY" && this.store.inventorySourceDependencies) {
      const result = await this.store.inventorySourceDependencies(scanId);
      if (result) await emit("source.dependencies_inventoried", { stageId, components: result.components, manifests: result.manifests });
    }
    if (stageId === "SBOM_GENERATION" && this.store.generateBinarySbom) {
      const result = await this.store.generateBinarySbom(scanId);
      if (result) await emit("binary.sbom_generated", { stageId, format: result.format, checksum: result.checksum, components: result.components });
    }
    if (stageId === "SBOM_GENERATION" && this.store.generateSourceSbom) {
      const result = await this.store.generateSourceSbom(scanId);
      if (result) await emit("source.sbom_generated", { stageId, format: result.format, checksum: result.checksum, components: result.components });
    }
    if (stageId === "QUALITY_GATE" && this.store.evaluateSourceQualityGate) {
      const result = await this.store.evaluateSourceQualityGate(scanId);
      if (result) await emit("source.quality_gate_evaluated", { stageId, status: result.status, failedRules: result.failedRules, warningRules: result.warningRules });
    }
    // Prompt 13 platform stages (§90): image resolution is engine work
    // (tag → digest + drift snapshot). Tool stages that reached the
    // platform path selected NO adapters (tools unavailable / no
    // cluster configured) — they complete honestly as degraded/skipped,
    // never simulated (§66 pattern).
    if (stageId === "IMAGE_RESOLUTION") {
      if (!this.store.resolveContainerImage) return "FAILED";
      const result = await this.store.resolveContainerImage(scanId);
      if (!result) {
        await emit("policy.denied", { stageId, reasonCode: "IMAGE_UNRESOLVABLE" });
        return "FAILED";
      }
      if (!result.skipped) {
        await emit("container.image_resolved", { stageId, imageRef: result.imageRef, digest: result.digest ?? null, digestKnown: !!result.digest });
        if (result.drift) await emit("container.image_drift_detected", { stageId, imageRef: result.imageRef, digest: result.digest ?? null });
      }
    }
    if (stageId === "IMAGE_VULNERABILITY_SCAN" || stageId === "MANIFEST_SCAN" || stageId === "KUBERNETES_POSTURE" || stageId === "DOCKER_POSTURE") {
      await emit("tool.failed", { stageId, reasonCode: "TOOL_UNAVAILABLE", degraded: true });
    }
    if (stageId === "CLUSTER_INVENTORY") {
      await emit("policy.denied", { stageId, reasonCode: "CLUSTER_NOT_CONFIGURED" });
    }
    if (stageId === "QUALITY_GATE" && this.store.evaluateContainerQualityGate) {
      const result = await this.store.evaluateContainerQualityGate(scanId);
      if (result) await emit("container.quality_gate_evaluated", { stageId, status: result.status, failedRules: result.failedRules, warningRules: result.warningRules });
    }
    // Prompt 14 platform stages (§86): CLOUD_AUTH validates the
    // registered account (missing hook or NOT_CONFIGURED fails the
    // scan honestly — FAIL_SCAN strategy); the section stages run
    // deterministic analysis over the persisted inventory;
    // CLOUD_COMPLIANCE assembles control assessments + drift + risk
    // paths; the cloud gate shares the QUALITY_GATE stage.
    if (stageId === "CLOUD_AUTH") {
      if (!this.store.validateCloudAccount) return "FAILED";
      const result = await this.store.validateCloudAccount(scanId);
      if (!result || result.status !== "VALIDATED") {
        await emit("policy.denied", { stageId, reasonCode: "CLOUD_NOT_CONFIGURED" });
        return "FAILED";
      }
      await emit("cloud.account_validated", { stageId, provider: result.provider ?? null });
    }
    if (["IAM_ANALYSIS", "NETWORK_ANALYSIS", "STORAGE_ANALYSIS", "ENCRYPTION_ANALYSIS", "LOGGING_ANALYSIS"].includes(stageId) && this.store.analyzeCloudSection) {
      const result = await this.store.analyzeCloudSection(scanId, stageId);
      if (result) {
        await emit("cloud.analysis_completed", { stageId, section: stageId, findings: result.findings, assessments: result.assessments });
        if (stageId === "IAM_ANALYSIS" && result.findings > 0) await emit("cloud.iam_risk_detected", { stageId, findings: result.findings });
      }
    }
    if (stageId === "CLOUD_COMPLIANCE" && this.store.assessCloudCompliance) {
      const result = await this.store.assessCloudCompliance(scanId);
      if (result) {
        await emit("cloud.compliance_assessed", { stageId, assessed: result.assessed, failed: result.failed });
        if (result.drift > 0) await emit("cloud.drift_detected", { stageId, count: result.drift });
      }
    }
    if (stageId === "QUALITY_GATE" && this.store.evaluateCloudQualityGate) {
      const result = await this.store.evaluateCloudQualityGate(scanId);
      if (result) await emit("cloud.quality_gate_evaluated", { stageId, status: result.status, failedRules: result.failedRules, warningRules: result.warningRules });
    }
    // Prompt 15 platform stages (§86): DOMAIN_DISCOVERY validates the
    // registered domain (missing hook or NOT_CONFIGURED fails the scan
    // honestly — FAIL_SCAN strategy); LDAP_POSTURE runs the DC/LDAP
    // analyzers over persisted inventory; GRAPH_COLLECTION builds the
    // identity graph (+ annotations + drift); ATTACK_PATH_ANALYSIS
    // models defensive paths over the graph — never executes them.
    if (stageId === "DOMAIN_DISCOVERY") {
      if (!this.store.validateDirectoryDomain) return "FAILED";
      const result = await this.store.validateDirectoryDomain(scanId);
      if (!result || result.status !== "VALIDATED") {
        await emit("policy.denied", { stageId, reasonCode: "AD_NOT_CONFIGURED" });
        return "FAILED";
      }
      await emit("ad.domain_validated", { stageId, domainRef: result.domainRef ?? null });
    }
    if (stageId === "LDAP_POSTURE" && this.store.analyzeDirectoryLdapPosture) {
      const result = await this.store.analyzeDirectoryLdapPosture(scanId);
      if (result) await emit("ad.ldap_posture_completed", { stageId, findings: result.findings, assessments: result.assessments });
    }
    if (stageId === "GRAPH_COLLECTION" && this.store.buildDirectoryGraph) {
      const result = await this.store.buildDirectoryGraph(scanId);
      if (result) {
        await emit("ad.graph_built", { stageId, nodes: result.nodes, edges: result.edges, privileged: result.privileged });
        if (result.privileged > 0) await emit("ad.privileged_identity_detected", { stageId, count: result.privileged });
        if (result.drift > 0) await emit("ad.drift_detected", { stageId, count: result.drift });
      }
    }
    if (stageId === "ATTACK_PATH_ANALYSIS" && this.store.analyzeAttackPaths) {
      const result = await this.store.analyzeAttackPaths(scanId);
      if (result) {
        await emit("ad.attack_paths_analyzed", { stageId, paths: result.paths });
        if (result.paths > 0) await emit("ad.attack_path_detected", { stageId, count: result.paths });
      }
    }
    // Prompt 17 platform stages (§10/§11): MOBILE_ARTIFACT_INTAKE
    // validates the registered build (missing hook or no build fails
    // the scan honestly — FAIL_SCAN strategy); MOBILE_METADATA_
    // EXTRACTION runs the platform extraction over the build's
    // registered artifacts (manifest/plist parse, secret scan, SCA);
    // MOBILE_MANIFEST_ANALYSIS runs posture over persisted inventory;
    // the mobile gate shares the QUALITY_GATE stage. Dynamic tool
    // stages that reached the platform path selected NO adapters (no
    // approved lab session / dynamic worker unavailable) — they
    // complete honestly as skipped, never simulated (§58/§73).
    if (stageId === "MOBILE_ARTIFACT_INTAKE") {
      if (!this.store.validateMobileBuild) return "FAILED";
      const result = await this.store.validateMobileBuild(scanId);
      if (!result) {
        await emit("policy.denied", { stageId, reasonCode: "MOBILE_BUILD_NOT_CONFIGURED" });
        return "FAILED";
      }
      await emit("mobile.build_validated", { stageId, buildHash: result.buildHash, platform: result.platform, artifactFormat: result.artifactFormat });
    }
    if (stageId === "MOBILE_METADATA_EXTRACTION" && this.store.extractMobileMetadata) {
      const result = await this.store.extractMobileMetadata(scanId);
      if (result) {
        await emit("mobile.metadata_extracted", { stageId, permissions: result.permissions, components: result.components, endpoints: result.endpoints, componentsScanned: result.componentsScanned });
        if (result.secrets > 0) await emit("mobile.secrets_detected", { stageId, count: result.secrets });
        if (result.endpoints > 0) await emit("mobile.endpoints_discovered", { stageId, count: result.endpoints, classification: "DISCOVERED_REFERENCE" });
      }
    }
    if (stageId === "MOBILE_MANIFEST_ANALYSIS" && this.store.analyzeMobileManifest) {
      const result = await this.store.analyzeMobileManifest(scanId);
      if (result) await emit("mobile.manifest_analyzed", { stageId, findings: result.findings, assessments: result.assessments });
    }
    if (stageId === "MOBILE_DYNAMIC_SESSION" || stageId === "MOBILE_TRAFFIC_ANALYSIS") {
      await emit("mobile.dynamic_session_skipped", { stageId, reasonCode: "MOBILE_DYNAMIC_NOT_CONFIGURED", degraded: true });
    }
    // Prompt 18 platform stages (§10/§11): BINARY_ARTIFACT_INTAKE
    // validates the registered artifact (missing hook or no artifact
    // fails the scan honestly — FAIL_SCAN strategy);
    // BINARY_METADATA_EXTRACTION runs the platform static analysis
    // over the artifact's registered payload (header parse, strings,
    // secrets, SCA); BINARY_DEBUG_SESSION evaluates the governed
    // debug-session policy (§64–§74) — without an approved session /
    // lab transport it completes as BLOCKED / NOT_PROVISIONED,
    // never simulated, never executed here.
    if (stageId === "BINARY_ARTIFACT_INTAKE") {
      if (!this.store.validateBinaryArtifact) return "FAILED";
      const result = await this.store.validateBinaryArtifact(scanId);
      if (!result) {
        await emit("policy.denied", { stageId, reasonCode: "BINARY_ARTIFACT_NOT_CONFIGURED" });
        return "FAILED";
      }
      await emit("binary.artifact_validated", { stageId, artifactHash: result.artifactHash, format: result.format });
    }
    if (stageId === "BINARY_METADATA_EXTRACTION" && this.store.extractBinaryMetadata) {
      const result = await this.store.extractBinaryMetadata(scanId);
      if (result) {
        await emit("binary.metadata_extracted", { stageId, sections: result.sections, functions: result.functions, dependencies: result.dependencies, componentsScanned: result.componentsScanned });
        if (result.secrets > 0) await emit("binary.secrets_detected", { stageId, count: result.secrets });
      }
    }
    if (stageId === "BINARY_DEBUG_SESSION") {
      if (this.store.evaluateBinaryDebugSession) {
        const result = await this.store.evaluateBinaryDebugSession(scanId);
        if (result) await emit("binary.debug_session_evaluated", { stageId, status: result.status, ...(result.reason ? { reason: result.reason } : {}) });
        else await emit("binary.debug_session_skipped", { stageId, reasonCode: "BINARY_DEBUG_NOT_CONFIGURED", degraded: true });
      } else {
        await emit("binary.debug_session_skipped", { stageId, reasonCode: "BINARY_DEBUG_NOT_CONFIGURED", degraded: true });
      }
    }
    if (stageId === "QUALITY_GATE" && this.store.evaluateBinaryQualityGate) {
      const result = await this.store.evaluateBinaryQualityGate(scanId);
      if (result) await emit("binary.quality_gate_evaluated", { stageId, status: result.status, failedRules: result.failedRules, warningRules: result.warningRules });
    }
    if (stageId === "QUALITY_GATE" && this.store.evaluateMobileQualityGate) {
      const result = await this.store.evaluateMobileQualityGate(scanId);
      if (result) await emit("mobile.quality_gate_evaluated", { stageId, status: result.status, failedRules: result.failedRules, warningRules: result.warningRules });
    }
    // Prompt 19 platform stages (§15): WIRELESS_CAPTURE_INTAKE
    // validates the registered environment (missing hook or no
    // environment fails the scan honestly — FAIL_SCAN strategy);
    // WIRELESS_POSTURE_ANALYSIS runs the deterministic posture pass
    // (encryption/rogue/drift/events) over persisted inventory; the
    // wireless gate shares the QUALITY_GATE stage. Tool stages that
    // reached the platform path selected NO adapters (no approved
    // sensor/capture) — they complete honestly as degraded, never
    // simulated (§8-pattern).
    if (stageId === "WIRELESS_CAPTURE_INTAKE") {
      if (!this.store.validateWirelessEnvironment) return "FAILED";
      const result = await this.store.validateWirelessEnvironment(scanId);
      if (!result) {
        await emit("policy.denied", { stageId, reasonCode: "WIRELESS_ENVIRONMENT_NOT_CONFIGURED" });
        return "FAILED";
      }
      await emit("wireless.environment_validated", { stageId, environmentId: result.environmentId, environmentRef: result.environmentRef ?? null });
    }
    if (stageId === "WIRELESS_PASSIVE_DISCOVERY" || stageId === "WIRELESS_PCAP_ANALYSIS") {
      await emit("wireless.collection_skipped", { stageId, reasonCode: "WIRELESS_SENSOR_NOT_CONFIGURED", degraded: true });
    }
    if (stageId === "WIRELESS_POSTURE_ANALYSIS" && this.store.analyzeWirelessPosture) {
      const result = await this.store.analyzeWirelessPosture(scanId);
      if (result) {
        await emit("wireless.posture_analyzed", { stageId, findings: result.findings, accessPoints: result.accessPoints });
        if (result.events > 0) await emit("wireless.security_event_detected", { stageId, count: result.events });
        if (result.drift > 0) await emit("wireless.drift_detected", { stageId, count: result.drift });
      }
    }
    if (stageId === "QUALITY_GATE" && this.store.evaluateWirelessQualityGate) {
      const result = await this.store.evaluateWirelessQualityGate(scanId);
      if (result) await emit("wireless.quality_gate_evaluated", { stageId, status: result.status, failedRules: result.failedRules, warningRules: result.warningRules });
    }
    return "COMPLETED";
  }

  private async skipRemaining(scanId: string, plan: ScanPlan, statuses: Map<string, string>): Promise<void> {
    for (const stage of plan.stages) {
      const s = statuses.get(stage.id) ?? "PENDING";
      if (!TERMINAL.has(s)) await this.store.updateStage(scanId, stage.id, { status: "SKIPPED", completedAt: new Date() });
    }
  }

  private async cancelRemaining(scanId: string, plan: ScanPlan, statuses: Map<string, string>): Promise<void> {
    for (const stage of plan.stages) {
      const s = statuses.get(stage.id) ?? "PENDING";
      if (!TERMINAL.has(s)) await this.store.updateStage(scanId, stage.id, { status: "CANCELLED", completedAt: new Date() });
    }
    await this.store.updateScan(scanId, { status: "CANCELLED", completedAt: new Date() });
  }

  private async skipDependents(
    scanId: string, plan: ScanPlan, failedStage: string,
    statuses: Map<string, string>,
    emit: (type: ScanEventRecord["type"], payload: ScanEventRecord["payload"]) => Promise<void>,
  ): Promise<void> {
    // Transitive dependents of the failed stage are skipped (§8).
    const dependents = new Map<string, string[]>();
    for (const s of plan.stages) for (const dep of s.dependencies) dependents.set(dep, [...(dependents.get(dep) ?? []), s.id]);
    const queue = [...(dependents.get(failedStage) ?? [])];
    const seen = new Set<string>();
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (seen.has(id)) continue;
      seen.add(id);
      const s = statuses.get(id) ?? "PENDING";
      if (!TERMINAL.has(s)) {
        await this.store.updateStage(scanId, id, { status: "SKIPPED", completedAt: new Date() });
        await emit("stage.skipped", { stageId: id, because: failedStage });
      }
      queue.push(...(dependents.get(id) ?? []));
    }
  }
}
