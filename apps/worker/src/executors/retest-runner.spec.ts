import { describe, expect, it } from "vitest";
import { RetestRunner, type RetestStore } from "./retest-runner";
import type { StageExecutionOutcome } from "./stage-executor";

/**
 * Prompt 11 §99 retest outcome tests: pass → RESOLVED, fail → REOPENED,
 * and a stage that could not run → FAILED (never a silent pass). The
 * store/executor are fakes; the production path drives the real
 * StageExecutor with all gates re-evaluated (§57).
 */

function fakeStore(produced: string[]): RetestStore & { completed: Array<{ outcome: string; detail: string }> } {
  const completed: Array<{ outcome: string; detail: string }> = [];
  return {
    completed,
    async prepareRetestExecution() {
      return { executionId: "exec-1", scanId: "child-scan", canonicalFingerprint: "fp-original" };
    },
    async retestScanFingerprints() { return produced; },
    async completeRetest(_id, outcome, detail) { completed.push({ outcome, detail }); },
  };
}

function fakeExecutor(outcome: StageExecutionOutcome) {
  return { run: async () => outcome };
}

describe("RetestRunner (§55–§58, §99)", () => {
  it("issue not reproduced → RESOLVED", async () => {
    const store = fakeStore([]);
    const runner = new RetestRunner(store, fakeExecutor({ status: "COMPLETED", assets: 0, findings: 0 }) as never);
    const result = await runner.runRetest("rt-1");
    expect(result).toEqual({ status: "COMPLETED", outcome: "RESOLVED" });
    expect(store.completed[0]?.outcome).toBe("RESOLVED");
  });

  it("issue reproduced → REOPENED", async () => {
    const store = fakeStore(["fp-original"]);
    const runner = new RetestRunner(store, fakeExecutor({ status: "COMPLETED", assets: 0, findings: 1 }) as never);
    const result = await runner.runRetest("rt-1");
    expect(result.outcome).toBe("REOPENED");
    expect(store.completed[0]?.outcome).toBe("REOPENED");
  });

  it("a DENIED stage (gates re-applied, §57) is a FAILED retest — never RESOLVED", async () => {
    const store = fakeStore([]);
    const runner = new RetestRunner(store, fakeExecutor({ status: "DENIED", reasonCode: "TARGET_NOT_VERIFIED" }) as never);
    const result = await runner.runRetest("rt-1");
    expect(result.status).toBe("FAILED");
    expect(store.completed[0]?.outcome).toBe("FAILED");
    expect(store.completed[0]?.detail).toContain("NOT verified fixed");
  });

  it("an unpreparable request is reported, not silently dropped", async () => {
    const store: RetestStore = {
      async prepareRetestExecution() { return null; },
      async retestScanFingerprints() { return []; },
      async completeRetest() {},
    };
    const runner = new RetestRunner(store, fakeExecutor({ status: "COMPLETED", assets: 0, findings: 0 }) as never);
    expect((await runner.runRetest("rt-x")).status).toBe("NOT_PREPARED");
  });
});
