import { describe, expect, it } from "vitest";
import { assertExecutionTransition, assertStageTransition, dependentOutcomeOnFailure } from "./state-machines";
import { finalScanStatus, monotonicProgress, progressForPlan } from "./progress";
import { buildScanPlan } from "./plan";
import { MockSecurityAdapter, ToolRegistry } from "@dsrclone/security-sdk";
import { classifyError, idempotencyKey, retryDecision, stageJobId } from "./idempotency";
import { ConcurrencyLimiter, clampLimit } from "./concurrency";
import { reconcileStaleExecution, workerCanRun, workerStatusFromHeartbeat } from "./recovery";

describe("stage + execution state machines (§18–§19)", () => {
  it("dependencies drive BLOCKED -> READY -> QUEUED -> RUNNING -> COMPLETED", () => {
    expect(() => assertStageTransition("BLOCKED", "READY")).not.toThrow();
    expect(() => assertStageTransition("READY", "QUEUED")).not.toThrow();
    expect(() => assertStageTransition("QUEUED", "RUNNING")).not.toThrow();
    expect(() => assertStageTransition("RUNNING", "COMPLETED")).not.toThrow();
    expect(() => assertStageTransition("COMPLETED", "RUNNING")).toThrow();
    expect(() => assertStageTransition("PENDING", "COMPLETED")).toThrow();
  });
  it("execution lifecycle includes PARSING/NORMALIZING and TIMED_OUT", () => {
    expect(() => assertExecutionTransition("RUNNING", "PARSING")).not.toThrow();
    expect(() => assertExecutionTransition("PARSING", "NORMALIZING")).not.toThrow();
    expect(() => assertExecutionTransition("NORMALIZING", "COMPLETED")).not.toThrow();
    expect(() => assertExecutionTransition("RUNNING", "TIMED_OUT")).not.toThrow();
    expect(() => assertExecutionTransition("COMPLETED", "RUNNING")).toThrow();
  });
  it("failure strategies decide dependent outcomes", () => {
    expect(dependentOutcomeOnFailure("FAIL_SCAN")).toBe("FAIL_SCAN");
    expect(dependentOutcomeOnFailure("SKIP_DEPENDENTS")).toBe("SKIP");
    expect(dependentOutcomeOnFailure("CONTINUE_WITH_PARTIAL_DATA")).toBe("READY");
  });
});

describe("weighted progress (§39)", () => {
  it("weights stages, counts RUNNING as half, and never moves backward", () => {
    const r = new ToolRegistry();
    r.register(new MockSecurityAdapter());
    const { plan } = buildScanPlan({
      scanId: "s", assessmentId: "a", targetId: "t", workspaceId: "w", organizationId: "o",
      profile: "PASSIVE_RECON", targetType: "DOMAIN", targetValue: "example.com", targetHost: "example.com",
      scope: { includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
      targetVerified: true, assessmentApproved: true, registry: r, selection: { executableSlugs: ["mock"] },
    });
    const status = new Map<string, string>(plan.stages.map((s) => [s.id, "PENDING"]));
    expect(progressForPlan(plan.stages, status)).toBe(0);
    for (const s of plan.stages) status.set(s.id, "COMPLETED");
    expect(progressForPlan(plan.stages, status)).toBe(100);
    status.set("PASSIVE_RECON", "RUNNING");
    const mid = progressForPlan(plan.stages, status);
    expect(mid).toBeLessThan(100);
    expect(monotonicProgress(95, mid)).toBe(95); // never backward
    expect(monotonicProgress(0, mid)).toBe(mid); // forward is allowed
  });
  it("rolls stage outcomes up into COMPLETED / PARTIAL / FAILED", () => {
    expect(finalScanStatus(["COMPLETED", "SKIPPED"])).toBe("COMPLETED");
    expect(finalScanStatus(["COMPLETED", "FAILED"])).toBe("PARTIAL");
    expect(finalScanStatus(["FAILED", "CANCELLED"])).toBe("FAILED");
  });
});

describe("idempotency + retries (§15, §29)", () => {
  it("job ids are deterministic per scan+stage+attempt", () => {
    expect(idempotencyKey("s1", "st1", 1)).toBe("s1:st1:1");
    expect(stageJobId("s1", "st1", 2)).toBe(stageJobId("s1", "st1", 2));
    expect(stageJobId("s1", "st1", 2)).not.toBe(stageJobId("s1", "st1", 1));
  });
  it("only transient/parser failures retry, with bounded backoff; policy/scope never retry", () => {
    expect(retryDecision("TRANSIENT", 1).retry).toBe(true);
    expect(retryDecision("TRANSIENT", 1).delayMs).toBe(1000);
    expect(retryDecision("TRANSIENT", 3).retry).toBe(false);
    expect(retryDecision("POLICY", 1).retry).toBe(false);
    expect(retryDecision("SCOPE", 1).retry).toBe(false);
    expect(retryDecision("TIMEOUT", 1).retry).toBe(false);
    expect(classifyError(new Error("policy denied"))).toBe("POLICY");
  });
});

describe("concurrency + recovery (§24, §51)", () => {
  it("limiter enforces per-key ceilings and profiles can only lower limits", () => {
    const limiter = new ConcurrencyLimiter();
    expect(limiter.tryAcquire("tool:mock", 1)).toBe(true);
    expect(limiter.tryAcquire("tool:mock", 1)).toBe(false);
    limiter.release("tool:mock");
    expect(limiter.tryAcquire("tool:mock", 1)).toBe(true);
    expect(clampLimit(99, 4)).toBe(4);
    expect(clampLimit(2, 4)).toBe(2);
  });
  it("heartbeat staleness uses thresholds; one missed beat is not OFFLINE", () => {
    const now = new Date("2026-01-01T00:01:00Z");
    expect(workerStatusFromHeartbeat({ lastHeartbeatAt: "2026-01-01T00:00:50Z", now, activeJobs: 0, capacity: 4 })).toBe("ONLINE");
    expect(workerStatusFromHeartbeat({ lastHeartbeatAt: "2026-01-01T00:00:50Z", now, activeJobs: 4, capacity: 4 })).toBe("BUSY");
    expect(workerStatusFromHeartbeat({ lastHeartbeatAt: "2026-01-01T00:00:10Z", now, activeJobs: 0, capacity: 4 })).toBe("DEGRADED");
    expect(workerStatusFromHeartbeat({ lastHeartbeatAt: "2025-12-31T23:58:00Z", now, activeJobs: 0, capacity: 4 })).toBe("OFFLINE");
    expect(workerCanRun(["WEB_CRAWLING"], ["WEB_CRAWLING"])).toBe(true);
    expect(workerCanRun(["WEB_CRAWLING"], ["MOBILE_STATIC_ANALYSIS"])).toBe(false);
  });
  it("recovery never re-runs completed work; orphaned running work fails honestly", () => {
    const now = new Date("2026-01-01T00:10:00Z");
    expect(reconcileStaleExecution({ id: "1", status: "COMPLETED" }, now)).toBe("LEAVE");
    expect(reconcileStaleExecution({ id: "2", status: "QUEUED" }, now)).toBe("REQUEUE");
    expect(reconcileStaleExecution({ id: "3", status: "RUNNING", workerLastHeartbeatAt: "2026-01-01T00:09:50Z" }, now)).toBe("LEAVE");
    expect(reconcileStaleExecution({ id: "4", status: "RUNNING", workerLastHeartbeatAt: "2026-01-01T00:00:00Z" }, now)).toBe("MARK_FAILED");
    expect(reconcileStaleExecution({ id: "5", status: "RUNNING", startedAt: "2026-01-01T00:00:00Z", timeoutSeconds: 60 }, now)).toBe("MARK_TIMED_OUT");
  });
});
