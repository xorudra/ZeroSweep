import { describe, expect, it } from "vitest";
import { MockSecurityAdapter, ToolRegistry } from "@dsrclone/security-sdk";
import { buildScanPlan, type ScanPlan, type ScanEventRecord } from "@dsrclone/orchestration";
import type { ScopeRules } from "@dsrclone/validation";
import { StageExecutor, type ExecutionContextRecord } from "./executors/stage-executor";
import { DagRunner, type ScanRunRecord, type ScanRunStore } from "./consumers/dag-runner";
import { processNormalizedResult } from "./executors/result-processor";
import type { ProcessedResult } from "./executors/result-processor";

/**
 * Prompt 4 §56–§61 scenarios against an in-memory store + fake dispatch
 * (the same shapes the Prisma store and BullMQ dispatcher implement):
 * mock E2E, deterministic failure, timeout, cancellation, policy denial.
 */

const SCOPE: ScopeRules = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };
const AUTH = {
  organizationId: "org-1", workspaceId: "ws-1", targetId: "t-1", targetOrganizationId: "org-1",
  assessmentId: "a-1", scanId: "scan-1", verificationStatus: "VERIFIED" as const,
  approvalStatus: "APPROVED" as const, requestedBy: "u-1",
};

interface ExecRec { id: string; stageType: string; adapterSlug: string; status: string; patch: Record<string, unknown> }

class FakeStore implements ScanRunStore {
  plan: ScanPlan;
  scanStatus = "QUEUED";
  progress = 0;
  stages = new Map<string, string>();
  executions = new Map<string, ExecRec>();
  events: ScanEventRecord[] = [];
  assets: ProcessedResult["assets"] = [];
  findings: ProcessedResult["findings"] = [];
  deadLetters: unknown[] = [];
  reportPending = false;
  paused = false;
  cancelled = false;
  simulationByStage: Record<string, ExecutionContextRecord["simulation"]> = {};
  verified = true;

  constructor(profile: "PASSIVE_RECON" | "WEB_BASELINE") {
    const registry = new ToolRegistry();
    registry.register(new MockSecurityAdapter());
    this.plan = buildScanPlan({
      scanId: "scan-1", assessmentId: "a-1", targetId: "t-1", workspaceId: "ws-1", organizationId: "org-1",
      profile, targetType: "DOMAIN", targetValue: "example.com", targetHost: "example.com",
      scope: SCOPE, targetVerified: true, assessmentApproved: true, registry,
      selection: { executableSlugs: ["mock", "local-echo"] },
    }).plan;
    for (const s of this.plan.stages) this.stages.set(s.type, s.dependencies.length === 0 ? "READY" : "BLOCKED");
    this.simulationByStage["PASSIVE_RECON"] = { fixture: true };
  }

  private gate() {
    return {
      auth: AUTH, targetHost: "example.com", scopeRules: SCOPE, targetExists: true,
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
    const id = `exec-${stageType}`;
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
      targetType: "DOMAIN", targetValue: "example.com", targetHost: "example.com", scopeRules: SCOPE,
      auth: AUTH, targetExists: true, targetWorkspaceId: "ws-1",
      targetVerified: this.verified, assessmentApproved: true, scopeValid: true,
      networkCapable: planned.networkCapable,
      simulation: this.simulationByStage[exec.stageType],
    };
  }
  async updateExecution(id: string, patch: Record<string, unknown>): Promise<void> {
    const exec = this.executions.get(id);
    if (!exec) return;
    Object.assign(exec.patch, patch);
    if (typeof patch.status === "string") exec.status = patch.status;
  }
  async recordEvent(event: ScanEventRecord): Promise<void> { this.events.push(event); }
  async persistResult(_scanId: string, _executionId: string, processed: ProcessedResult): Promise<{ assets: number; findings: number }> {
    this.assets.push(...processed.assets);
    this.findings.push(...processed.findings);
    return { assets: processed.assets.length, findings: processed.findings.length };
  }
  async recordDeadLetter(entry: unknown): Promise<void> { this.deadLetters.push(entry); }
}

function makeRunner(store: FakeStore): DagRunner {
  const registry = new ToolRegistry();
  registry.register(new MockSecurityAdapter());
  return new DagRunner(store, new StageExecutor(registry, store));
}

describe("mock E2E pipeline (§56)", () => {
  it("PASSIVE_RECON scan completes end-to-end: plan → stages → mock adapter → artifact → normalized asset + mock finding → report pending", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    const result = await makeRunner(store).run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.scanStatus).toBe("COMPLETED");
    expect([...store.stages.values()].every((s) => s === "COMPLETED")).toBe(true);
    expect(store.assets).toHaveLength(1);
    expect(store.assets[0]).toMatchObject({ host: "example.com", scopeStatus: "IN_SCOPE" });
    expect(store.findings).toHaveLength(1);
    expect(store.findings[0]!.isMock).toBe(true);
    expect(store.findings[0]!.title).toContain("[MOCK]");
    expect(store.reportPending).toBe(true);
    const types = store.events.map((e) => e.type);
    expect(types[0]).toBe("scan.started");
    expect(types).toContain("asset.discovered");
    expect(types).toContain("finding.created");
    expect(types[types.length - 1]).toBe("scan.completed");
    // Event ordering: every stage.started precedes its stage.completed.
    const startedIdx = types.indexOf("stage.started");
    expect(startedIdx).toBeLessThan(types.indexOf("stage.completed"));
  });

  it("WEB_BASELINE completes with the full web stage chain", async () => {
    const store = new FakeStore("WEB_BASELINE");
    const result = await makeRunner(store).run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.stages.get("SAFE_VULNERABILITY_SCAN")).toBe("COMPLETED");
    expect(store.stages.get("CRAWLING")).toBe("COMPLETED");
  });
});

describe("failure, timeout, cancellation (§57–§59)", () => {
  it("deterministic tool failure continues per failure strategy and ends PARTIAL", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    store.simulationByStage["ASSET_DISCOVERY"] = { failWith: "TOOL_ERROR" };
    const result = await makeRunner(store).run("scan-1");
    expect(result.status).toBe("PARTIAL");
    expect(store.stages.get("ASSET_DISCOVERY")).toBe("PARTIAL"); // FAIL_STAGE_CONTINUE
    expect(store.stages.get("DNS_RESOLUTION")).toBe("COMPLETED"); // dependents still ran
    expect(store.deadLetters.length).toBeGreaterThan(0);
  });

  it("simulated timeout marks the execution TIMED_OUT and the stage PARTIAL", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    store.simulationByStage["PASSIVE_RECON"] = { fixture: true, failWith: "TIMEOUT" };
    const result = await makeRunner(store).run("scan-1");
    expect(result.status).toBe("PARTIAL");
    expect(store.executions.get("exec-PASSIVE_RECON")!.status).toBe("TIMED_OUT");
  });

  it("cancelling a delayed scan stops new stages and converges to CANCELLED", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    store.simulationByStage["PASSIVE_RECON"] = { fixture: true, delayMs: 400 };
    const running = makeRunner(store).run("scan-1");
    await new Promise((r) => setTimeout(r, 60));
    store.cancelled = true;
    store.scanStatus = "CANCELLED";
    const result = await running;
    expect(result.status).toBe("CANCELLED");
    expect(store.findings).toHaveLength(0); // cancelled before persistence
    const types = store.events.map((e) => e.type);
    expect(types[types.length - 1]).toBe("scan.cancelled");
  });

  it("pausing stops scheduling new stages", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    store.paused = true;
    const result = await makeRunner(store).run("scan-1");
    expect(result.status).toBe("PAUSED");
    expect(store.findings).toHaveLength(0);
  });
});

describe("policy + scope enforcement (§61, §33)", () => {
  it("policy-denied execution never runs the adapter and persists nothing", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    store.verified = false; // target no longer verified at execution time
    const registry = new ToolRegistry();
    registry.register(new MockSecurityAdapter());
    const executor = new StageExecutor(registry, store);
    await store.ensureExecution("scan-1", "PASSIVE_RECON", "mock", 1);
    const outcome = await executor.run({ kind: "STAGE_EXECUTION", scanId: "scan-1", stageId: "PASSIVE_RECON", toolExecutionId: "exec-PASSIVE_RECON", attempt: 1 });
    expect(outcome.status).toBe("DENIED");
    expect(store.findings).toHaveLength(0);
    expect(store.assets).toHaveLength(0);
    expect(store.events.some((e) => e.type === "policy.denied")).toBe(true);
    expect(store.executions.get("exec-PASSIVE_RECON")!.status).toBe("FAILED");
  });

  it("an unverified target fails the authorization gate stage — scan FAILED, nothing executed", async () => {
    const store = new FakeStore("PASSIVE_RECON");
    store.verified = false;
    const result = await makeRunner(store).run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.executions.size).toBe(0);
  });

  it("discovered out-of-scope assets are recorded OUT_OF_SCOPE, never in-scope", () => {
    const processed = processNormalizedResult(
      { assets: [{ host: "third-party-cdn.example.net", type: "HOST" }, { host: "API.Example.com", type: "HOST" }], services: [], endpoints: [], technologies: [], findings: [], artifacts: [], metrics: {}, mock: true },
      { scopeRules: SCOPE, toolExecutionId: "exec-1" },
    );
    expect(processed.assets.find((a) => a.host === "third-party-cdn.example.net")!.scopeStatus).toBe("OUT_OF_SCOPE");
    expect(processed.assets.find((a) => a.host === "api.example.com")!.scopeStatus).toBe("IN_SCOPE"); // canonicalized
  });
});
