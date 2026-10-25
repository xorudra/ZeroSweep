import { describe, expect, it } from "vitest";
import { MockSecurityAdapter, ToolRegistry } from "@zerosweep/security-sdk";
import { StageExecutor } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { processNormalizedResult } from "./executors/result-processor";
import { FakeStore, TEST_SCOPE as SCOPE } from "./testing/fake-store";

/**
 * Prompt 4 §56–§61 scenarios against the in-memory FakeStore + fake dispatch
 * (the same shapes the Prisma store and BullMQ dispatcher implement):
 * mock E2E, deterministic failure, timeout, cancellation, policy denial.
 * The Prompt 5 real-adapter scenarios live in recon.e2e.spec.ts.
 */

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
    expect(store.executions.get("exec-PASSIVE_RECON-mock")!.status).toBe("TIMED_OUT");
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
    const outcome = await executor.run({ kind: "STAGE_EXECUTION", scanId: "scan-1", stageId: "PASSIVE_RECON", toolExecutionId: "exec-PASSIVE_RECON-mock", attempt: 1 });
    expect(outcome.status).toBe("DENIED");
    expect(store.findings).toHaveLength(0);
    expect(store.assets).toHaveLength(0);
    expect(store.events.some((e) => e.type === "policy.denied")).toBe(true);
    expect(store.executions.get("exec-PASSIVE_RECON-mock")!.status).toBe("FAILED");
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
