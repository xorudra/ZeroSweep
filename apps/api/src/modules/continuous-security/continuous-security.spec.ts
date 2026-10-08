import { MonitoringPolicyService } from "./monitoring/monitoring-policy.service";
import { SecuritySchedulerService } from "./schedules/security-scheduler.service";
import { SnapshotService } from "./snapshots/snapshot.service";
import { DriftService } from "./drift/drift.service";
import { WorkflowService } from "./workflows/workflow.service";
import { NotificationRouterService } from "./notifications/notification-router.service";
import { AutoRetestService } from "./retesting/auto-retest.service";
import { MonitoringAnalyticsService } from "./analytics/monitoring-analytics.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (same pattern as prior phase specs).          */
/* ------------------------------------------------------------------ */

/** Minimal call-recording stub (Jest globals provide describe/it). */
function mockFn(impl: (...args: never[]) => Promise<unknown>) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => {
    calls.push(args);
    return impl(...(args as never[]));
  };
  return Object.assign(fn, { calls });
}
type Row = Record<string, unknown> & { id: string };

function cmp(a: unknown, b: unknown): number {
  const av = a instanceof Date ? a.getTime() : (a as number);
  const bv = b instanceof Date ? b.getTime() : (b as number);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    if ("not" in c) {
      if (c.not === null) { if (value === null || value === undefined) return false; }
      else if (value === c.not) return false;
      continue;
    }
    if ("gte" in c && cmp(value, c.gte) < 0) return false;
    if ("lte" in c && cmp(value, c.lte) > 0) return false;
    if ("gt" in c && cmp(value, c.gt) <= 0) return false;
    if ("lt" in c && cmp(value, c.lt) >= 0) return false;
    if (!("gte" in c) && !("lte" in c) && !("gt" in c) && !("lt" in c)) return false;
  }
  return true;
}

let seq = 0;
function makeTable(name: string, db: Record<string, { rows: Row[] }>) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      // Monotonic clock: strictly increasing createdAt so desc/asc
      // ordering between rows created in the same millisecond is
      // deterministic (real Postgres timestamps behave this way at
      // the resolutions these tests exercise).
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      // Mirror @default(now()) columns the services order by.
      if (row.capturedAt === undefined) row.capturedAt = stamp;
      if (row.detectedAt === undefined) row.detectedAt = stamp;
      rows.push(row);
      return row;
    },
    async createMany({ data }: { data: Row[] }) {
      for (const d of data) await table.create({ data: d });
      return { count: data.length };
    },
    async findUnique({ where }: { where: Record<string, unknown> }) {
      return rows.find((r) => matches(r, where)) ?? null;
    },
    async findFirst(args: { where?: Record<string, unknown>; include?: Record<string, boolean>; orderBy?: Record<string, string> } = {}) {
      const list = await table.findMany({ ...args, take: 1 });
      return list[0] ?? null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number; orderBy?: Record<string, string> | Array<Record<string, string>>; include?: Record<string, unknown> } = {}) {
      let out = rows.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy[0] : args.orderBy;
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0]!;
        out = [...out].sort((a, b) => cmp(a[field], b[field]) * (dir === "desc" ? -1 : 1));
      }
      if (args.take) out = out.slice(0, args.take);
      if (args.include && name === "assessment") {
        for (const row of out) {
          if (args.include.target) row.target = db.target!.rows.find((t: Row) => t.id === row.targetId) ?? null;
          if (args.include.scope) row.scope = db.scope!.rows.find((s: Row) => s.id === row.scopeId) ?? null;
        }
      }
      return out;
    },
    async update({ where, data }: { where: Record<string, unknown>; data: Row }) {
      const row = rows.find((r) => matches(r, where));
      if (!row) throw new Error(`row not found in ${name}`);
      Object.assign(row, data);
      return row;
    },
    async updateMany({ where, data }: { where?: Record<string, unknown>; data: Row }) {
      let count = 0;
      for (const r of rows) if (matches(r, where)) { Object.assign(r, data); count++; }
      return { count };
    },
    async delete({ where }: { where: Record<string, unknown> }) {
      const i = rows.findIndex((r) => matches(r, where));
      if (i >= 0) rows.splice(i, 1);
      return {};
    },
    async count(args: { where?: Record<string, unknown> } = {}) {
      return rows.filter((r) => matches(r, args.where)).length;
    },
    async groupBy(args: { by: string[]; where?: Record<string, unknown> }) {
      const field = args.by[0]!;
      const counts = new Map<unknown, number>();
      for (const r of rows.filter((x) => matches(x, args.where))) counts.set(r[field], (counts.get(r[field]) ?? 0) + 1);
      return [...counts.entries()].map(([v, _count]) => ({ [field]: v, _count }));
    },
  };
  return table;
}

const TABLES = [
  "monitoringPolicy", "securitySchedule", "scheduleRun", "schedulerLease", "schedulerSettings",
  "maintenanceWindow", "blackoutWindow", "securityPostureSnapshot", "assetSnapshot", "assetSnapshotEntry",
  "findingSnapshot", "findingSnapshotEntry", "attackSurfaceChange", "driftEvent", "findingDriftEvent",
  "riskDriftEvent", "autoRetestPolicy", "securityWorkflow", "workflowExecution", "notificationPolicy",
  "alertEscalationPolicy", "securityNotification", "aiDailySecuritySummary", "assessment", "target",
  "scope", "user", "workspace", "membership", "scan", "finding", "asset", "reportSchedule",
  "retestRequest", "kevRecord", "epssRecord", "cveRecord", "deadLetterJob",
] as const;

function makeFake() {
  const db: Record<string, ReturnType<typeof makeTable>> = {};
  for (const t of TABLES) db[t] = makeTable(t, db);
  return db as unknown as Record<string, ReturnType<typeof makeTable>> & {
    [K in (typeof TABLES)[number]]: ReturnType<typeof makeTable>;
  };
}

/* ------------------------------------------------------------------ */

const ADMIN: RequestUser = { id: "u-admin", email: "rudra@example.com", organizationId: "org-1", role: "OWNER" };
const VIEWER: RequestUser = { id: "u-viewer", email: "viewer@example.com", organizationId: "org-1", role: "VIEWER" };
const WS = "ws-1";
const T = (iso: string) => new Date(iso);

function makeStack() {
  const prisma = makeFake();
  const audit = { record: mockFn(async () => ({})) };
  const policies = new MonitoringPolicyService(prisma as never, audit as never);
  const orchestration = { startScan: mockFn(async () => ({ scanId: "scan-new", reused: false, stagesCreated: 3 })) };
  const reports = {
    createReport: mockFn(async () => ({ id: "report-1" })),
    generate: mockFn(async () => ({ id: "report-1" })),
  };
  const validations = { createValidation: mockFn(async () => ({ id: "validation-1" })) };
  const retestStub = { requestRetest: mockFn(async () => ({ id: "retest-1" })) };
  const autoRetest = new AutoRetestService(prisma as never, audit as never, retestStub as never);
  const snapshots = new SnapshotService(prisma as never, audit as never);
  const drift = new DriftService(prisma as never, audit as never, snapshots);
  const notifications = new NotificationRouterService(prisma as never, audit as never);
  const workflows = new WorkflowService(prisma as never, audit as never, notifications, autoRetest);
  const analytics = new MonitoringAnalyticsService(prisma as never);
  const scheduler = new SecuritySchedulerService(
    prisma as never, audit as never, policies, orchestration as never, reports as never,
    validations as never, autoRetest, snapshots, drift,
  );
  scheduler.resolver = async () => ["93.184.216.34"];
  notifications.resolver = async () => ["93.184.216.34"];
  return { prisma, audit, policies, orchestration, reports, validations, retestStub, autoRetest, snapshots, drift, notifications, workflows, analytics, scheduler };
}

async function seedScanScenario(stack: ReturnType<typeof makeStack>, overrides: Record<string, unknown> = {}) {
  const { prisma } = stack;
  await prisma.user.create({ data: { id: ADMIN.id, email: ADMIN.email, name: "Rudra" } as never });
  await prisma.workspace.create({ data: { id: WS, organizationId: "org-1", name: "Default" } as never });
  await prisma.membership.create({ data: { id: "m-1", userId: ADMIN.id, organizationId: "org-1", role: "OWNER" } as never });
  await prisma.target.create({ data: { id: "t-1", workspaceId: WS, name: "Example", type: "WEB_APPLICATION", value: "example.com", status: "VERIFIED", verified: true, createdBy: ADMIN.id } as never });
  await prisma.scope.create({ data: { id: "scope-1", workspaceId: WS, targetId: "t-1", name: "Scope", rules: { includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] } } as never });
  await prisma.assessment.create({
    data: {
      id: "a-1", workspaceId: WS, targetId: "t-1", scopeId: "scope-1", name: "Web baseline",
      profile: "WEB_BASELINE", status: "APPROVED", createdBy: ADMIN.id, ...overrides,
    } as never,
  });
}

async function seedSchedule(stack: ReturnType<typeof makeStack>, overrides: Record<string, unknown> = {}) {
  const row = await stack.prisma.securitySchedule.create({
    data: {
      id: "sched-1", workspaceId: WS, name: "Daily web baseline", kind: "SCAN", assessmentId: "a-1",
      profile: "WEB_BASELINE", expression: "0 2 * * *", frequency: "DAILY", timezone: "UTC",
      nextRunAt: T("2026-10-08T02:00:00Z"), enabled: true, paused: false, failureCount: 0,
      missedRunPolicy: "RUN_ONCE", allowConcurrent: false, createdBy: ADMIN.id, ...overrides,
    } as never,
  });
  return row;
}

describe("policy + schedule creation gates (§8/§9)", () => {
  it("refuses prohibited and approval-required profiles in monitoring policies", async () => {
    const { policies } = makeStack();
    await expect(policies.createPolicy(ADMIN, WS, { name: "x", scanProfile: "BINARY_CONTROLLED_DEBUG", targetSelector: {} })).rejects.toThrow(/PROHIBITED_AUTOMATION/);
    await expect(policies.createPolicy(ADMIN, WS, { name: "x", scanProfile: "NETWORK_INTERNAL", targetSelector: {} })).rejects.toThrow(/APPROVAL_REQUIRED/);
    const ok = await policies.createPolicy(ADMIN, WS, { name: "ok", scanProfile: "WEB_BASELINE", targetSelector: {} });
    expect(ok.scanProfile).toBe("WEB_BASELINE");
  });

  it("schedule creation re-checks authorization at creation time (§8)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack, { status: "DRAFT" });
    await expect(stack.scheduler.createSchedule(ADMIN, WS, { name: "s", kind: "SCAN", assessmentId: "a-1" })).rejects.toThrow(/APPROVED/);
  });

  it("viewers cannot manage schedules (§87)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await expect(stack.scheduler.createSchedule(VIEWER, WS, { name: "s", kind: "SCAN", assessmentId: "a-1" })).rejects.toThrow(/lacks permission/);
  });
});

describe("scheduler tick — fake clock (§7/§19/§97/§98)", () => {
  it("a daily schedule produces exactly one run at its instant, then advances", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack);
    const first = await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    expect(first.acquired).toBe(true);
    expect(stack.orchestration.startScan.calls).toHaveLength(1);
    let runs = await stack.prisma.scheduleRun.findMany({ where: { workspaceId: WS } });
    expect(runs).toHaveLength(1);
    expect(runs[0]!.status).toBe("ENQUEUED");
    expect(runs[0]!.scanId).toBe("scan-new");
    const schedule = await stack.prisma.securitySchedule.findFirst({ where: { id: "sched-1" } });
    expect(new Date(schedule!.nextRunAt as string).toISOString()).toBe("2026-10-09T02:00:00.000Z");
    // Same instant again: nothing due, no duplicate run.
    await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    runs = await stack.prisma.scheduleRun.findMany({ where: { workspaceId: WS } });
    expect(runs).toHaveLength(1);
    // Next day: exactly one more.
    await stack.scheduler.tick(T("2026-10-09T02:00:00Z"), "node-1");
    runs = await stack.prisma.scheduleRun.findMany({ where: { workspaceId: WS } });
    expect(runs).toHaveLength(2);
  });

  it("two scheduler instances cannot both hold the lease (§98)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack);
    const a = await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    expect(a.acquired).toBe(true);
    const second = new SecuritySchedulerService(stack.prisma as never, stack.audit as never, stack.policies, stack.orchestration as never, stack.reports as never, stack.validations as never, stack.autoRetest, stack.snapshots, stack.drift);
    const b = await second.tick(T("2026-10-08T02:00:00Z"), "node-2");
    expect(b.acquired).toBe(false);
    expect(stack.orchestration.startScan.calls).toHaveLength(1);
  });

  it("re-executing the same instant is idempotent via the run key (§19)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    const schedule = await seedSchedule(stack);
    const instant = T("2026-10-08T02:00:00Z");
    const one = await stack.scheduler.executeScheduleRun(schedule as never, instant);
    const two = await stack.scheduler.executeScheduleRun(schedule as never, instant);
    expect(one.status).toBe("ENQUEUED");
    expect(two.reasonCode).toBe("ALREADY_MATERIALIZED");
    expect(await stack.prisma.scheduleRun.count({ where: { workspaceId: WS } })).toBe(1);
  });

  it("missed runs collapse under RUN_ONCE — never an unlimited backlog (§20)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack, { nextRunAt: T("2026-10-05T02:00:00Z") });
    await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    const runs = await stack.prisma.scheduleRun.findMany({ where: { workspaceId: WS } });
    expect(runs.filter((r) => r.status === "ENQUEUED")).toHaveLength(1);
    expect(runs.filter((r) => r.status === "SKIPPED" && r.reasonCode === "MISSED_RUN_SKIPPED")).toHaveLength(3);
  });

  it("paused schedules never fire", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack, { paused: true });
    await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });
});

describe("fire-time gates (§25/§26/§99/§100/§101/§102)", () => {
  it("expired authorization BLOCKS the run — schedules never resurrect approvals (§99)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack);
    await stack.prisma.assessment.update({ where: { id: "a-1" }, data: { status: "DRAFT" } as never });
    await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    const runs = await stack.prisma.scheduleRun.findMany({ where: { workspaceId: WS } });
    expect(runs).toHaveLength(1);
    expect(runs[0]!.status).toBe("BLOCKED");
    expect(runs[0]!.reasonCode).toBe("AUTHORIZATION_EXPIRED");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("DNS drift to a private address BLOCKS the run (§100)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack);
    stack.scheduler.resolver = async () => ["10.0.0.9"];
    await stack.scheduler.tick(T("2026-10-08T02:00:00Z"), "node-1");
    const runs = await stack.prisma.scheduleRun.findMany({ where: { workspaceId: WS } });
    expect(runs[0]!.status).toBe("BLOCKED");
    expect(["PROTECTED_DESTINATION", "OUT_OF_SCOPE"]).toContain(runs[0]!.reasonCode);
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("blackout windows defer the run to the blackout end (§101)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    const schedule = await seedSchedule(stack);
    await stack.prisma.blackoutWindow.create({
      data: { id: "bo-1", workspaceId: WS, name: "Release freeze", startsAt: T("2026-10-08T00:00:00Z"), endsAt: T("2026-10-08T12:00:00Z"), createdBy: ADMIN.id } as never,
    });
    const outcome = await stack.scheduler.executeScheduleRun(schedule as never, T("2026-10-08T02:00:00Z"));
    expect(outcome.status).toBe("DEFERRED");
    expect(outcome.reasonCode).toBe("BLACKOUT");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("an equivalent running scan prevents a duplicate (§102)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    const schedule = await seedSchedule(stack);
    await stack.prisma.scan.create({
      data: { id: "scan-running", workspaceId: WS, assessmentId: "a-1", status: "RUNNING", plan: { profile: "WEB_BASELINE" }, requestedBy: ADMIN.id } as never,
    });
    const outcome = await stack.scheduler.executeScheduleRun(schedule as never, T("2026-10-08T02:00:00Z"));
    expect(outcome.status).toBe("SKIPPED");
    expect(outcome.reasonCode).toBe("DUPLICATE_RUN");
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });

  it("run-now still passes every gate (§82)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack);
    await stack.prisma.target.update({ where: { id: "t-1" }, data: { verified: false } as never });
    const outcome = await stack.scheduler.runNow(ADMIN, WS, "sched-1");
    expect(outcome.status).toBe("BLOCKED");
    expect(outcome.reasonCode).toBe("TARGET_NOT_VERIFIED");
  });
});

describe("schedule kinds", () => {
  it("INTEL_SYNC records the honest not-configured outcome (§49)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    const schedule = await seedSchedule(stack, { kind: "INTEL_SYNC", assessmentId: null, profile: null });
    const outcome = await stack.scheduler.executeScheduleRun(schedule as never, T("2026-10-08T02:00:00Z"));
    expect(outcome.status).toBe("SKIPPED");
    expect(outcome.reasonCode).toBe("INTEL_SOURCE_NOT_CONFIGURED");
  });

  it("REPORT schedules execute the Prompt 20 definition", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await stack.prisma.reportSchedule.create({
      data: { id: "rs-1", workspaceId: WS, name: "Weekly client report", reportType: "CLIENT", cronExpression: "0 3 * * 1", recipients: [], formats: ["PDF"], enabled: true, createdBy: ADMIN.id } as never,
    });
    const schedule = await seedSchedule(stack, { kind: "REPORT", assessmentId: null, profile: null, reportScheduleId: "rs-1" });
    const outcome = await stack.scheduler.executeScheduleRun(schedule as never, T("2026-10-08T02:00:00Z"));
    expect(outcome.status).toBe("COMPLETED");
    expect(outcome.reportId).toBe("report-1");
    expect(stack.reports.generate.calls).toHaveLength(1);
  });

  it("REVALIDATION creates approval-gated Prompt 16 requests — never executions (§67)", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await stack.prisma.scan.create({ data: { id: "scan-1", workspaceId: WS, assessmentId: "a-1", status: "COMPLETED", requestedBy: ADMIN.id } as never });
    await stack.prisma.finding.create({
      data: {
        id: "f-tls", workspaceId: WS, scanId: "scan-1", title: "TLS 1.0 enabled", vulnClass: "TLS",
        host: "example.com", port: 443, sources: ["testssl"], sourceDomain: "WEB",
        lifecycleStatus: "REMEDIATED", status: "OPEN", severity: "MEDIUM", verificationStatus: "UNVERIFIED",
        confidence: 90, kevListed: false, fingerprint: "fp-tls",
      } as never,
    });
    const schedule = await seedSchedule(stack, { kind: "REVALIDATION", profile: null });
    const outcome = await stack.scheduler.executeScheduleRun(schedule as never, T("2026-10-08T02:00:00Z"));
    expect(outcome.status).toBe("PENDING_APPROVAL");
    expect(stack.validations.createValidation.calls).toHaveLength(1);
    expect(stack.orchestration.startScan.calls).toHaveLength(0);
  });
});

describe("snapshots + drift (§29–§48)", () => {
  async function seedAssets(stack: ReturnType<typeof makeStack>) {
    await stack.prisma.asset.create({
      data: {
        id: "asset-1", workspaceId: WS, targetId: "t-1", host: "example.com", ip: "93.184.216.34", type: "HOST",
        scopeStatus: "IN_SCOPE", criticality: "HIGH", sources: ["nmap"],
        services: [{ port: 443, name: "https", product: null }], endpoints: [],
      } as never,
    });
  }

  it("captures immutable snapshots and detects a NEW_PORT surface change", async () => {
    const stack = makeStack();
    await seedAssets(stack);
    await stack.snapshots.captureSnapshots(WS, "MANUAL");
    const asset = await stack.prisma.asset.findFirst({ where: { id: "asset-1" } });
    (asset!.services as unknown[]).push({ port: 8443, name: "https-alt", product: null });
    await stack.snapshots.captureSnapshots(WS, "MANUAL");
    const result = await stack.drift.runDrift(WS);
    expect(result.surfaceChanges).toBeGreaterThan(0);
    const changes = await stack.prisma.attackSurfaceChange.findMany({ where: { workspaceId: WS } });
    expect(changes.some((c) => c.type === "NEW_PORT")).toBe(true);
    const posture = await stack.prisma.securityPostureSnapshot.findMany({ where: { workspaceId: WS } });
    expect(posture).toHaveLength(2);
  });

  it("KEV listing drift re-scores the finding without any scan (§110/§50)", async () => {
    const stack = makeStack();
    await stack.prisma.finding.create({
      data: {
        id: "f-kev", workspaceId: WS, title: "Known exploited CVE", cve: "CVE-2026-0001", vulnClass: "CVE",
        sources: ["nuclei"], sourceDomain: "WEB", lifecycleStatus: "IN_PROGRESS", status: "OPEN",
        severity: "HIGH", verificationStatus: "UNVERIFIED", confidence: 80, kevListed: false,
        epssScore: 0.1, intelCvssScore: 7.5, riskScore: 40, fingerprint: "fp-kev",
        intelSnapshot: { kevListed: false, epssScore: 0.1, cvssScore: 7.5 },
      } as never,
    });
    await stack.prisma.kevRecord.create({ data: { id: "kev-1", cveId: "CVE-2026-0001" } as never });
    await stack.prisma.epssRecord.create({ data: { id: "epss-1", cveId: "CVE-2026-0001", score: 0.9 } as never });
    await stack.prisma.cveRecord.create({ data: { id: "cve-1", cveId: "CVE-2026-0001", cvssScore: 9.8 } as never });
    const result = await stack.drift.runIntelDrift(WS);
    expect(result.riskDriftEvents).toBeGreaterThan(0);
    const events = await stack.prisma.riskDriftEvent.findMany({ where: { workspaceId: WS } });
    expect(events.some((e) => e.type === "KEV_ADDED")).toBe(true);
    const finding = await stack.prisma.finding.findFirst({ where: { id: "f-kev" } });
    expect(finding!.kevListed).toBe(true);
    expect(finding!.riskCalcVersion).toBe("risk-v3.0");
  });
});

describe("workflows (§61–§64)", () => {
  it("rejects code-shaped workflow definitions", async () => {
    const { workflows } = makeStack();
    await expect(workflows.createWorkflow(ADMIN, WS, {
      name: "bad", trigger: "FINDING_CREATED", conditions: [],
      actions: [{ type: "CREATE_NOTIFICATION", params: { script: "id" } }],
    })).rejects.toThrow(/arbitrary code/);
  });

  it("executes typed actions and guards loops", async () => {
    const stack = makeStack();
    await stack.prisma.finding.create({
      data: {
        id: "f-1", workspaceId: WS, title: "Critical thing", sources: [], lifecycleStatus: "CONFIRMED",
        status: "OPEN", severity: "CRITICAL", priority: "P2", verificationStatus: "CONFIRMED", confidence: 90, kevListed: false, fingerprint: "fp-1", tags: [],
      } as never,
    });
    await stack.prisma.notificationPolicy.create({
      data: {
        id: "np-1", workspaceId: WS, name: "in-app", eventTypes: ["FINDING_VERIFIED"], channels: ["IN_APP"],
        recipients: [], dedupWindowMinutes: 60, emergencySeverities: ["CRITICAL"], throttlePerHour: 60, enabled: true, createdBy: ADMIN.id,
      } as never,
    });
    const wf = await stack.workflows.createWorkflow(ADMIN, WS, {
      name: "crit-response", trigger: "FINDING_VERIFIED",
      conditions: [{ field: "severity", operator: "eq", value: "CRITICAL" }],
      actions: [
        { type: "CREATE_NOTIFICATION", params: { channel: "IN_APP" } },
        { type: "SET_PRIORITY", params: { priority: "P0" } },
      ],
    });
    const executions = await stack.workflows.executeForEvent(WS, {
      trigger: "FINDING_VERIFIED", severity: "CRITICAL", eventId: "evt-1", findingId: "f-1", title: "Critical thing",
    });
    expect(executions).toHaveLength(1);
    expect(executions[0]!.status).toBe("COMPLETED");
    const finding = await stack.prisma.finding.findFirst({ where: { id: "f-1" } });
    expect(finding!.priority).toBe("P0");
    const notes = await stack.prisma.securityNotification.findMany({ where: { workspaceId: WS } });
    expect(notes).toHaveLength(1);
    expect(notes[0]!.status).toBe("SENT");
    // Loop guard: the workflow in its own lineage never re-fires.
    const looped = await stack.workflows.executeForEvent(WS, {
      trigger: "FINDING_VERIFIED", severity: "CRITICAL", eventId: "evt-2", findingId: "f-1", title: "Critical thing",
    }, { lineage: [wf.id as string] });
    expect(looped[0]!.status).toBe("BLOCKED_LOOP");
  });
});

describe("notifications (§66–§74/§115/§116)", () => {
  const event = {
    type: "FINDING_CREATED", workspaceId: WS, findingId: "f-1", severity: "HIGH",
    contentHash: "same-content", title: "Finding", detail: "d",
  };

  it("dedupes identical alerts inside the window (§116)", async () => {
    const stack = makeStack();
    await stack.prisma.notificationPolicy.create({
      data: {
        id: "np-1", workspaceId: WS, name: "p", eventTypes: ["FINDING_CREATED"], channels: ["IN_APP"],
        recipients: [], dedupWindowMinutes: 60, emergencySeverities: ["CRITICAL"], throttlePerHour: 60, enabled: true, createdBy: ADMIN.id,
      } as never,
    });
    const first = await stack.notifications.routeEvent(WS, event);
    expect(first[0]!.status).toBe("SENT");
    const second = await stack.notifications.routeEvent(WS, event);
    expect(second[0]!.status).toBe("SUPPRESSED_DEDUP");
  });

  it("unconfigured external providers are recorded, never faked as sent (§66)", async () => {
    const stack = makeStack();
    await stack.prisma.notificationPolicy.create({
      data: {
        id: "np-2", workspaceId: WS, name: "mail", eventTypes: ["FINDING_CREATED"], channels: ["EMAIL"],
        recipients: [], dedupWindowMinutes: 60, emergencySeverities: ["CRITICAL"], throttlePerHour: 60, enabled: true, createdBy: ADMIN.id,
      } as never,
    });
    const routed = await stack.notifications.routeEvent(WS, event);
    expect(routed[0]!.status).toBe("RECORDED_NOT_DELIVERED");
    const rows = await stack.prisma.securityNotification.findMany({ where: { workspaceId: WS } });
    expect(rows[0]!.providerStatus).toBe("NOT_CONFIGURED");
  });

  it("webhook policies refuse SSRF destinations at save time (§115)", async () => {
    const stack = makeStack();
    await expect(stack.notifications.createPolicy(ADMIN, WS, {
      name: "hook", eventTypes: ["FINDING_CREATED"], channels: ["WEBHOOK"],
      webhook: { url: "https://169.254.169.254/hook", allowlist: [] },
    })).rejects.toThrow(/refused/);
    const ok = await stack.notifications.createPolicy(ADMIN, WS, {
      name: "hook-ok", eventTypes: ["FINDING_CREATED"], channels: ["WEBHOOK"],
      webhook: { url: "https://hooks.example.com/notify", allowlist: ["hooks.example.com"], signingSecretRef: "vault:webhook-signing" },
    });
    expect(ok.webhookUrl).toBe("https://hooks.example.com/notify");
    expect((ok as Row).signingSecretRef).toBe("vault:webhook-signing");
  });
});

describe("auto-retest (§51–§55)", () => {
  async function seedRetest(stack: ReturnType<typeof makeStack>) {
    await stack.prisma.autoRetestPolicy.create({
      data: { id: "arp-1", workspaceId: WS, enabled: true, triggers: ["REMEDIATION_MARKER", "SCHEDULED"], maxPerDay: 50, createdBy: ADMIN.id } as never,
    });
    await stack.prisma.finding.create({
      data: {
        id: "f-tls", workspaceId: WS, title: "TLS 1.0 enabled", vulnClass: "TLS", host: "example.com", port: 443,
        sources: ["testssl"], sourceDomain: "WEB", lifecycleStatus: "REMEDIATED", status: "OPEN",
        severity: "MEDIUM", verificationStatus: "UNVERIFIED", confidence: 90, kevListed: false, fingerprint: "fp-tls",
      } as never,
    });
    await stack.prisma.finding.create({
      data: {
        id: "f-rce", workspaceId: WS, title: "RCE exploitation proof required", vulnClass: "RCE EXPLOITATION", host: "example.com",
        sources: ["nuclei"], sourceDomain: "WEB", lifecycleStatus: "REMEDIATED", status: "OPEN",
        severity: "CRITICAL", verificationStatus: "UNVERIFIED", confidence: 90, kevListed: false, fingerprint: "fp-rce",
      } as never,
    });
  }

  it("eligible findings retest through the governed path; prohibited ones are refused", async () => {
    const stack = makeStack();
    await seedRetest(stack);
    const ok = await stack.autoRetest.requestRetest(ADMIN, WS, "f-tls", "REMEDIATION_MARKER");
    expect(ok.requested).toBe(true);
    expect(stack.retestStub.requestRetest.calls).toHaveLength(1);
    await expect(stack.autoRetest.requestRetest(ADMIN, WS, "f-rce", "REMEDIATION_MARKER")).rejects.toThrow(/refused/);
  });

  it("a disabled policy fails closed", async () => {
    const stack = makeStack();
    await seedRetest(stack);
    await stack.prisma.autoRetestPolicy.update({ where: { id: "arp-1" }, data: { enabled: false } as never });
    await expect(stack.autoRetest.requestRetest(ADMIN, WS, "f-tls", "REMEDIATION_MARKER")).rejects.toThrow(/disabled/);
  });
});

describe("tenant isolation (§120)", () => {
  it("schedules and runs never leak across workspaces", async () => {
    const stack = makeStack();
    await seedScanScenario(stack);
    await seedSchedule(stack);
    await stack.prisma.securitySchedule.create({
      data: { id: "sched-other", workspaceId: "ws-2", name: "Other", kind: "INTEL_SYNC", expression: "0 2 * * *", frequency: "DAILY", timezone: "UTC", nextRunAt: T("2026-10-08T02:00:00Z"), enabled: true, paused: false, failureCount: 0, missedRunPolicy: "RUN_ONCE", allowConcurrent: false, createdBy: ADMIN.id } as never,
    });
    const mine = await stack.scheduler.listSchedules(ADMIN, WS);
    expect(mine.map((s) => s.id)).toEqual(["sched-1"]);
    await expect(stack.scheduler.getSchedule(ADMIN, "ws-2", "sched-1")).rejects.toThrow(/not found/);
    const health = await stack.analytics.health(ADMIN, WS);
    expect(health.activeSchedules).toBe(1);
  });
});


