import { BadRequestException, NotFoundException } from "@nestjs/common";
import { OrchestrationService } from "./orchestration.service";
import { ScanEventsService } from "./scan-events.service";
import { OrchestrationController } from "./orchestration.controller";

/**
 * Prompt 4 API tests (§47–§49, §60–§61): plan preview executes nothing,
 * start-scan enforces the authorization/scope gates, pause/resume/cancel obey
 * the state machine, and the live stream is tenant-isolated before subscribing.
 */

const user = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const foreignUser = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

const SCOPE = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [443], allowedPaths: [], excludedPaths: [] };

function makePrisma(overrides: { verified?: boolean; status?: string; targetValue?: string } = {}) {
  const state = {
    scans: new Map<string, Record<string, unknown>>(),
    events: [] as Array<Record<string, unknown>>,
    stages: [] as Array<Record<string, unknown>>,
  };
  const assessment = {
    id: "a-1", workspaceId: "ws-org-1", profile: "PASSIVE_RECON",
    status: overrides.status ?? "APPROVED", scopeId: "s-1",
    // Independent approval (run-2 gate): creator u-2, approver u-3; the
    // acting user is u-1.
    createdBy: "u-2", approvedBy: "u-3",
    target: { id: "t-1", type: "DOMAIN", value: overrides.targetValue ?? "example.com", verified: overrides.verified ?? true },
    scope: { rules: SCOPE },
  };
  const prisma = {
    workspace: {
      findFirst: async ({ where }: never) => {
        const org = (where as { organizationId: string }).organizationId;
        return { id: `ws-${org}`, organizationId: org };
      },
    },
    assessment: { findFirst: async () => assessment },
    scan: {
      create: async ({ data }: never) => {
        const scan = { id: "scan-1", ...(data as Record<string, unknown>) };
        state.scans.set("scan-1", scan);
        return scan;
      },
      update: async ({ data }: never) => {
        const scan = { ...state.scans.get("scan-1"), ...(data as Record<string, unknown>) };
        state.scans.set("scan-1", scan);
        return scan;
      },
      findFirst: async ({ where }: never) => {
        const w = where as { id: string; workspaceId: string };
        const scan = state.scans.get(w.id);
        if (!scan || scan.workspaceId !== w.workspaceId) return null;
        return { ...scan, assessment, stages: [], executions: [] };
      },
      count: async () => 0,
      findMany: async () => [],
    },
    scanPlan: { create: async () => ({ id: "plan-1" }) },
    // Prompt 8: no scanner instances registered in this world — plan-time
    // connector health is honestly NOT_CONFIGURED for every product.
    scannerInstance: { findMany: async () => [] },
    scanStage: {
      createMany: async ({ data }: never) => { state.stages.push(...(data as Array<Record<string, unknown>>)); return { count: (data as unknown[]).length }; },
      updateMany: async () => ({ count: 0 }),
    },
    scanEvent: {
      create: async ({ data }: never) => { state.events.push(data as Record<string, unknown>); return data; },
      findMany: async () => state.events,
      count: async () => state.events.length,
    },
    finding: { groupBy: async () => [{ severity: "INFORMATIONAL", _count: 1 }] },
    asset: { count: async () => 1 },
    workerNode: { findMany: async () => [{ workerId: "worker-1", status: "ONLINE" }] },
    deadLetterJob: { findMany: async () => [] },
  };
  return { prisma, state, assessment };
}

function makeService(overrides?: { verified?: boolean; status?: string; targetValue?: string }) {
  const { prisma, state, assessment } = makePrisma(overrides);
  const audit = { record: async () => undefined };
  const queue = { calls: 0, enqueueScanOrchestration: async () => { queue.calls++; return true; } };
  const events = new ScanEventsService(prisma as never);
  const service = new OrchestrationService(prisma as never, audit as never, queue as never, events);
  return { service, prisma, state, assessment, queue, events };
}

describe("OrchestrationService (Prompt 4)", () => {
  it("plan preview returns stages/selection and persists + executes nothing (§46)", async () => {
    const { service, state, queue } = makeService();
    const plan = await service.previewPlan(user as never, "a-1");
    expect(plan.executesScan).toBe(false);
    expect(plan.stages.map((s) => s.type)).toContain("PASSIVE_RECON");
    expect(plan.stages.find((s) => s.type === "PASSIVE_RECON")!.selectedAdapters[0]!.simulation).toBe(true);
    expect(state.scans.size).toBe(0);
    expect(queue.calls).toBe(0);
  });

  it("start scan: verified + approved + in-scope → plan persisted, stages created, job queued (§47)", async () => {
    const { service, state } = makeService();
    const res = await service.startScan(user as never, "a-1");
    expect(res.status).toBe("QUEUED");
    expect(res.queueEnqueued).toBe(true);
    expect(state.stages.length).toBe(res.plan.stages.length);
    expect(state.events.map((e) => e.type)).toEqual(["scan.created", "scan.queued"]);
  });

  it("start scan is REFUSED for unverified target, unapproved assessment, out-of-scope target (§61)", async () => {
    await expect(makeService({ verified: false }).service.startScan(user as never, "a-1")).rejects.toThrow(BadRequestException);
    await expect(makeService({ status: "PENDING_APPROVAL" }).service.startScan(user as never, "a-1")).rejects.toThrow(/not approved/i);
    await expect(makeService({ targetValue: "other.org" }).service.startScan(user as never, "a-1")).rejects.toThrow(/outside the approved scope/i);
  });

  it("pause/resume/cancel follow the state machine; cancel is idempotent (§26–§27)", async () => {
    const { service, state } = makeService();
    await service.startScan(user as never, "a-1");
    state.scans.get("scan-1")!.status = "RUNNING";
    const paused = await service.pauseScan(user as never, "scan-1");
    expect(paused.status).toBe("PAUSED");
    await expect(service.pauseScan(user as never, "scan-1")).rejects.toThrow(BadRequestException); // PAUSED -> PAUSED illegal
    const cancelled = await service.cancelScan(user as never, "scan-1");
    expect(cancelled.status).toBe("CANCELLED");
    const again = await service.cancelScan(user as never, "scan-1");
    expect(again.status).toBe("CANCELLED"); // idempotent, no throw
    await expect(service.resumeScan(user as never, "scan-1")).rejects.toThrow(BadRequestException); // terminal
  });

  it("resume re-evaluates gates: a target unverified since pause refuses resume (§27)", async () => {
    const ctx = makeService();
    await ctx.service.startScan(user as never, "a-1");
    ctx.state.scans.get("scan-1")!.status = "PAUSED";
    ctx.assessment.target.verified = false;
    await expect(ctx.service.resumeScan(user as never, "scan-1")).rejects.toThrow(/Resume refused/);
  });

  it("scan details are tenant-isolated and include severity counts (§48, §60)", async () => {
    const { service } = makeService();
    await service.startScan(user as never, "a-1");
    const details = await service.getScanDetails(user as never, "scan-1");
    expect(details.findingCounts).toEqual({ INFORMATIONAL: 1 });
    expect(details.assetCount).toBe(1);
    await expect(service.getScanDetails(foreignUser as never, "scan-1")).rejects.toThrow(NotFoundException);
  });
});

describe("OrchestrationController live stream (§41, §60)", () => {
  it("refuses to subscribe a foreign tenant to a scan stream (404 before any event)", async () => {
    const { service, prisma, state, events } = makeService();
    await service.startScan(user as never, "a-1");
    const ctrl = new OrchestrationController(service, events, prisma as never);
    const stream = await ctrl.stream(user as never, "scan-1");
    expect(stream).toBeDefined();
    // The foreign tenant resolves to their own workspace, where this scan id
    // does not exist — subscription is refused before any event can leak.
    await expect(ctrl.stream(foreignUser as never, "scan-1")).rejects.toThrow(NotFoundException);
    void state;
  });

  it("exposes no arbitrary-execution route (§64)", () => {
    const methods = Object.getOwnPropertyNames(OrchestrationController.prototype);
    expect(methods.join(",")).not.toMatch(/execute|command|shell|run/i);
  });
});
