import {
  buildDag, dependentOutcomeOnFailure, evaluateAuthorizationGate, finalScanStatus,
  makeEvent, monotonicProgress, progressForPlan, readyStages, type GateInput,
  type ScanPlan, type ScanEventRecord,
} from "@dsrclone/orchestration";
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
}

export type StageDispatcher = (job: StageJobData) => Promise<StageExecutionOutcome>;

const TERMINAL = new Set(["COMPLETED", "PARTIAL", "FAILED", "SKIPPED", "CANCELLED"]);

export class DagRunner {
  constructor(
    private readonly store: ScanRunStore,
    private readonly executor: StageExecutor,
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

        const adapter = planned.selectedAdapters[0]!;
        const execution = await this.store.ensureExecution(scanId, node.id, adapter.slug, 1);
        const outcome = await dispatch({ kind: "STAGE_EXECUTION", scanId, stageId: node.id, toolExecutionId: execution.id, attempt: 1 });

        if (outcome.status === "COMPLETED" || outcome.status === "ALREADY_COMPLETED") {
          await this.store.updateStage(scanId, node.id, { status: "COMPLETED", progress: 100, completedAt: new Date() });
          await emit("stage.completed", { stageId: node.id });
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
    void scanId;
    if (stageId === "AUTHORIZATION_CHECK" || stageId === "SCOPE_VALIDATION") {
      const gate = evaluateAuthorizationGate(run.gate);
      if (!gate.allowed) {
        await emit(gate.reasonCode === "TARGET_OUT_OF_SCOPE" ? "scope.violation" : "policy.denied", { stageId, reasonCode: gate.reasonCode });
        return "FAILED";
      }
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
