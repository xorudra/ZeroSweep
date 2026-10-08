import { evaluateLifecycleTransition } from "@dsrclone/security-sdk";
import { CaseStateService } from "./case-state.service";
import { RemediationCasesService } from "./cases.service";
import { TriageService } from "./triage.service";
import { OwnershipService } from "./ownership.service";
import { RemediationSlaService } from "./sla.service";
import { RemediationPlansService } from "./plans.service";
import {
  RemediationTicketsService, UnconfiguredTicketProvider,
  type RemediationTicketProvider, type TicketProviderRegistry,
} from "./tickets.service";
import { RemediationVerificationService } from "./verification.service";
import { RemediationClosureService } from "./closure.service";
import { RemediationExceptionsService } from "./exceptions.service";
import { RemediationCampaignsService } from "./campaigns.service";
import { RemediationRegressionService } from "./regression.service";
import { RemediationAnalyticsService } from "./analytics.service";
import { RemediationAiService } from "./ai.service";
import { RemediationReportsService } from "./reports.service";
import { RemediationBulkService } from "./bulk.service";
import { RemediationTickService } from "./tick.service";
import { NotificationRouterService } from "../continuous-security/notifications/notification-router.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Prompt 31 API tests (§130–§153). FIXTURE-ONLY: the fake Prisma below
 * is an in-memory store; the ticket provider is a fixture double; the
 * retest collaborator is a stub recording that verification rode the
 * governed P11 path. No scanner runs, no network is touched, and every
 * clock is driven explicitly.
 */

/* ------------------------------ fake prisma ------------------------------ */

type Row = Record<string, unknown>;
let seq = 0;

function valEq(a: unknown, b: unknown): boolean {
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime();
  if (a instanceof Date && typeof b === "string") return a.getTime() === new Date(b).getTime();
  return a === b;
}

function matches(row: Row, where: Row = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    if (cond === undefined) continue;
    if (key === "OR") { if (!(cond as Row[]).some((w) => matches(row, w))) return false; continue; }
    if (key === "AND") { if (!(cond as Row[]).every((w) => matches(row, w))) return false; continue; }
    const value = row[key];
    if (cond !== null && typeof cond === "object" && !(cond instanceof Date) && !Array.isArray(cond)) {
      const ops = cond as Row;
      const opKeys = Object.keys(ops);
      const isOps = opKeys.every((k) => ["in", "notIn", "not", "has", "contains", "gte", "lte", "gt", "lt", "equals"].includes(k));
      if (isOps) {
        if ("in" in ops && !(ops.in as unknown[]).some((v) => valEq(value, v))) return false;
        if ("notIn" in ops && (ops.notIn as unknown[]).some((v) => valEq(value, v))) return false;
        if ("not" in ops) {
          if (ops.not === null) { if (value === null || value === undefined) return false; }
          else if (valEq(value, ops.not)) return false;
        }
        if ("has" in ops && !(Array.isArray(value) && value.includes(ops.has))) return false;
        if ("contains" in ops && !(typeof value === "string" && value.toLowerCase().includes(String(ops.contains).toLowerCase()))) return false;
        if ("gte" in ops && !(((value as Date)?.getTime?.() ?? (value as number)) >= ((ops.gte as Date)?.getTime?.() ?? (ops.gte as number)))) return false;
        if ("lte" in ops && !(((value as Date)?.getTime?.() ?? (value as number)) <= ((ops.lte as Date)?.getTime?.() ?? (ops.lte as number)))) return false;
        if ("gt" in ops && !(((value as Date)?.getTime?.() ?? (value as number)) > ((ops.gt as Date)?.getTime?.() ?? (ops.gt as number)))) return false;
        if ("lt" in ops && !(((value as Date)?.getTime?.() ?? (value as number)) < ((ops.lt as Date)?.getTime?.() ?? (ops.lt as number)))) return false;
        if ("equals" in ops && !valEq(value, ops.equals)) return false;
        continue;
      }
      if (!matches(row, ops)) return false;
      continue;
    }
    if (!valEq(value, cond)) return false;
  }
  return true;
}

const MODEL_DEFAULTS: Record<string, Row> = {
  remediationSlaPolicy: { version: 1, active: true, isDefault: false, verificationRequired: true, requiredCleanObservations: 1 },
  remediationCase: { status: "NEW", verificationState: "NOT_REQUESTED", regressionCount: 0 },
  remediationWorkItem: { status: "PENDING", failureCount: 0 },
  remediationVerificationJob: { status: "QUEUED", cleanObservations: 0, requiredCleanObservations: 1 },
  remediationSlaSnapshot: { state: "ON_TRACK", pausedDurationMs: 0 },
  remediationException: { status: "PENDING" },
  riskException: { status: "PENDING" },
  remediationCampaign: { status: "ACTIVE" },
};

function makeModel(store: Row[], defaults: Row = {}) {
  const applyOrder = (rows: Row[], orderBy?: Row) => {
    if (!orderBy) return rows;
    const [field, dir] = Object.entries(orderBy)[0] ?? [];
    if (!field) return rows;
    return [...rows].sort((a, b) => {
      const av = a[field] as never; const bv = b[field] as never;
      const cmp = av < bv ? -1 : av > bv ? 1 : 0;
      return dir === "desc" ? -cmp : cmp;
    });
  };
  return {
    findMany: async (args: { where?: Row; orderBy?: Row; take?: number; skip?: number; select?: Row } = {}) => {
      let rows = store.filter((r) => matches(r, args.where));
      rows = applyOrder(rows, args.orderBy);
      if (args.skip) rows = rows.slice(args.skip);
      if (args.take) rows = rows.slice(0, args.take);
      return rows.map((r) => {
        if (!args.select) return { ...r };
        const out: Row = {};
        for (const k of Object.keys(args.select)) out[k] = r[k];
        return out;
      });
    },
    findFirst: async (args: { where?: Row; orderBy?: Row } = {}) => {
      const rows = store.filter((r) => matches(r, args.where));
      const ordered = applyOrder(rows, args.orderBy);
      return ordered[0] ? { ...ordered[0] } : null;
    },
    findUnique: async (args: { where?: Row }) => {
      const row = store.find((r) => matches(r, args.where));
      return row ? { ...row } : null;
    },
    count: async (args: { where?: Row } = {}) => store.filter((r) => matches(r, args.where)).length,
    create: async (args: { data: Row }) => {
      const row: Row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), ...defaults, ...args.data };
      store.push(row);
      return { ...row };
    },
    update: async (args: { where: Row; data: Row }) => {
      const row = store.find((r) => matches(r, args.where));
      if (!row) throw new Error("record to update not found");
      Object.assign(row, args.data, { updatedAt: new Date() });
      return { ...row };
    },
    updateMany: async (args: { where?: Row; data: Row }) => {
      let n = 0;
      for (const row of store) if (matches(row, args.where)) { Object.assign(row, args.data); n++; }
      return { count: n };
    },
    deleteMany: async (args: { where?: Row } = {}) => {
      let n = 0;
      for (let i = store.length - 1; i >= 0; i--) if (matches(store[i]!, args.where)) { store.splice(i, 1); n++; }
      return { count: n };
    },
    upsert: async (args: { where: Row; create: Row; update: Row }) => {
      // Compound unique keys ({ integrationId_findingId: {...} }) match on parts.
      const flat: Row = {};
      for (const [k, v] of Object.entries(args.where)) {
        if (v !== null && typeof v === "object" && !(v instanceof Date)) Object.assign(flat, v);
        else flat[k] = v;
      }
      const existing = store.find((r) => matches(r, flat));
      if (existing) { Object.assign(existing, args.update, { updatedAt: new Date() }); return { ...existing }; }
      const row: Row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), ...defaults, ...args.create };
      store.push(row);
      return { ...row };
    },
  };
}

const MODEL_NAMES = [
  "workspace", "finding", "asset", "findingComment", "findingHistory",
  "remediationCase", "remediationStatusHistory", "remediationTriage", "remediationAssignment",
  "remediationSlaPolicy", "remediationSlaSnapshot", "remediationSlaPause", "remediationPlan",
  "remediationWorkItem", "remediationTicket", "remediationFixClaim",
  "remediationVerificationJob", "remediationVerificationEvidence", "remediationException",
  "riskException", "remediationCampaign", "remediationCampaignCase",
  "remediationRegressionEvent", "remediationReportSnapshot",
  "patchRecord", "componentVulnerabilityMatch", "softwareComponent", "notificationPolicy",
] as const;

function makePrisma(seed: Partial<Record<(typeof MODEL_NAMES)[number], Row[]>> = {}) {
  const stores = new Map<string, Row[]>();
  const prisma: Record<string, unknown> = {};
  for (const name of MODEL_NAMES) {
    const store = (seed[name] ?? []).map((r) => ({ ...r }));
    stores.set(name, store);
    prisma[name] = makeModel(store, MODEL_DEFAULTS[name] ?? {});
  }
  return { prisma: prisma as never, stores };
}

/* ------------------------------ collaborators ------------------------------ */

const admin: RequestUser = { id: "u-admin", email: "a@example.com", role: "ADMIN", organizationId: "org-1" };
const engineer: RequestUser = { id: "u-eng", email: "e@example.com", role: "SECURITY_ENGINEER", organizationId: "org-1" };
const analyst: RequestUser = { id: "u-analyst", email: "an@example.com", role: "ANALYST", organizationId: "org-1" };
const viewer: RequestUser = { id: "u-viewer", email: "v@example.com", role: "VIEWER", organizationId: "org-1" };

const DAY = 86_400_000;
const NOW = new Date("2026-10-08T06:00:00.000Z");

function findingSeed(over: Row = {}): Row {
  return {
    id: "f-1", workspaceId: "ws-1", organizationId: "org-1",
    title: "Log4Shell RCE", description: "fixture finding", status: "OPEN",
    lifecycleStatus: "IN_PROGRESS", severity: "CRITICAL", priority: "P1",
    cve: "CVE-2021-44228", cwe: "CWE-917", vulnClass: "sca", detectionKind: "SCA",
    kevListed: true, riskScore: 90, riskBand: "CRITICAL", riskFactors: [{ factor: "kev", value: true, contribution: 30 }],
    riskExplanation: { summary: "KEV-listed RCE" }, businessImpact: null, remediation: "upgrade log4j",
    host: "198.51.100.10", endpoint: null, assetId: "a-1", repositoryId: null,
    componentPurl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    dependencyScope: "DIRECT", imageRef: null, fixedVersion: null,
    fingerprint: "fp-log4shell", duplicateOfId: null, tags: ["internet-facing"],
    assignedToId: null, assignedToTeam: null, slaPolicyId: null, dueAt: null,
    resolvedAt: null, firstSeen: new Date(NOW.getTime() - 10 * DAY), lastSeen: new Date(NOW),
    createdAt: new Date(NOW.getTime() - 10 * DAY), updatedAt: new Date(NOW),
    ...over,
  };
}

function policySeed(over: Row = {}): Row {
  return {
    id: "pol-1", workspaceId: "ws-1", name: "Default remediation SLA", version: 3,
    isDefault: true, active: true, rules: { P0: 24, P1: 72, P2: 168, CRITICAL: 72, HIGH: 168 },
    conditions: null, warningThresholds: { warningPct: 0.5, atRiskPct: 0.8 }, escalation: null,
    verificationRequired: true, requiredCleanObservations: 1, createdBy: "u-admin",
    createdAt: new Date(NOW), updatedAt: new Date(NOW),
    ...over,
  };
}

/** A working fixture ticket provider (stands in for a configured P24
 *  connector): creates + serves tickets from memory. */
class FixtureTicketProvider implements RemediationTicketProvider {
  tickets = new Map<string, { status: string; closed: boolean }>();
  failNext = false;
  async createTicket() {
    if (this.failNext) { this.failNext = false; throw new Error("provider 503 (fixture)"); }
    const id = `FIX-${this.tickets.size + 1}`;
    this.tickets.set(id, { status: "OPEN", closed: false });
    return { externalId: id, externalUrl: `https://tickets.example.invalid/${id}`, status: "OPEN" };
  }
  async fetchTicket(externalId: string) {
    const t = this.tickets.get(externalId);
    if (!t) throw new Error("unknown ticket");
    return { externalId, status: t.status, closed: t.closed };
  }
  async healthCheck() { return { ok: true, detail: "fixture provider" }; }
}

/** Minimal governed lifecycle stub: applies the REAL SDK lifecycle
 *  machine to the fake finding store, like VulnerabilityService does. */
function makeVulnerabilities(prisma: never, stores: Map<string, Row[]>) {
  return {
    transition: async (user: RequestUser, workspaceId: string, id: string, input: { to: string; reason?: string; reviewerId?: string; riskAcceptance?: { approverId: string; expiresAt: Date } }) => {
      const store = stores.get("finding")!;
      const row = store.find((r) => r.id === id && r.workspaceId === workspaceId);
      if (!row) throw new Error("finding not found");
      const verdict = evaluateLifecycleTransition({
        from: row.lifecycleStatus as never, to: input.to as never, actorId: user.id,
        reason: input.reason, reviewerId: input.reviewerId,
        riskAcceptance: input.riskAcceptance ? { approverId: input.riskAcceptance.approverId, expiresAt: input.riskAcceptance.expiresAt } : undefined,
      });
      if (!verdict.ok) throw new Error(verdict.error ?? "transition rejected");
      row.lifecycleStatus = input.to;
      if (input.to === "RESOLVED") row.resolvedAt = new Date();
      return { view: { ...row } };
    },
    applyEnrichment: async (_user: RequestUser, _ws: string, id: string) => {
      const row = stores.get("finding")!.find((r) => r.id === id);
      return { view: row, enrichment: {}, risk: { score: row?.riskScore ?? 0, band: row?.riskBand ?? "LOW" } };
    },
  };
}

function makeWorld(seed: Partial<Record<(typeof MODEL_NAMES)[number], Row[]>> = {}, provider?: RemediationTicketProvider) {
  const { prisma, stores } = makePrisma({
    workspace: [{ id: "ws-1", organizationId: "org-1", name: "WS1" }],
    finding: [findingSeed()],
    asset: [{ id: "a-1", workspaceId: "ws-1", criticality: "HIGH", exposure: "PUBLIC" }],
    remediationSlaPolicy: [policySeed()],
    ...seed,
  });
  const auditEntries: Row[] = [];
  const audit = { record: async (e: Row) => { auditEntries.push(e); return e; } } as never;
  const published: Row[] = [];
  const events = { publish: async (e: Row) => { published.push(e); return { id: "evt" }; } } as never;
  const notifications = new NotificationRouterService(prisma, audit);
  const state = new CaseStateService(prisma, audit, events);
  const ownership = new OwnershipService(prisma, state);
  const sla = new RemediationSlaService(prisma, state, notifications);
  const cases = new RemediationCasesService(prisma, state, ownership, sla);
  const vulnerabilities = makeVulnerabilities(prisma, stores) as never;
  const triage = new TriageService(prisma, state, vulnerabilities);
  const plans = new RemediationPlansService(prisma, state);
  const providers: TicketProviderRegistry = new Map();
  providers.set("JIRA", provider ?? new UnconfiguredTicketProvider());
  const tickets = new RemediationTicketsService(prisma, state, providers);
  const retestCalls: Row[] = [];
  const retests = {
    requestRetest: async (user: RequestUser, ws: string, findingId: string, reason: string) => {
      retestCalls.push({ user: user.id, ws, findingId, reason });
      const finding = stores.get("finding")!.find((r) => r.id === findingId);
      if ((finding as Row)?.gateDeny) throw new Error("retest gate denied: no approved assessment (fixture)");
      return { id: "rt-1", status: "QUEUED" };
    },
  } as never;
  const verification = new RemediationVerificationService(prisma, state, sla, retests, vulnerabilities);
  const closure = new RemediationClosureService(prisma, state, sla);
  const exceptions = new RemediationExceptionsService(prisma, state, vulnerabilities);
  const campaigns = new RemediationCampaignsService(prisma, state, cases);
  const regressions = new RemediationRegressionService(prisma, state, vulnerabilities, notifications);
  const analytics = new RemediationAnalyticsService(prisma);
  const ai = new RemediationAiService(prisma, state, cases, plans);
  const reports = new RemediationReportsService(prisma, cases, analytics, sla);
  const bulk = new RemediationBulkService(state, ownership, sla, tickets, verification);
  const tick = new RemediationTickService(sla, exceptions, regressions, tickets);
  return {
    prisma, stores, auditEntries, published, state, ownership, sla, cases, triage, plans,
    tickets, verification, closure, exceptions, campaigns, regressions, analytics, ai,
    reports, bulk, tick, retestCalls,
  };
}

async function caseAtStatus(w: ReturnType<typeof makeWorld>, status: string, findingOver: Row = {}) {
  // Seed a case directly at a status with a matching finding.
  const finding = findingSeed(findingOver);
  w.stores.get("finding")!.length = 0;
  w.stores.get("finding")!.push(finding);
  const kase: Row = {
    id: "case-1", organizationId: "org-1", workspaceId: "ws-1", findingId: "f-1",
    status, priority: "P1", ownerType: "USER", ownerId: "u-eng", teamId: null,
    ownershipConfidence: "VERIFIED", slaPolicyId: "pol-1", dueAt: new Date(NOW.getTime() + 2 * DAY),
    remediationPlanId: null, verificationState: "NOT_REQUESTED", regressionCount: 0,
    lastRegressionAt: null, verifiedFixedAt: status === "VERIFIED_FIXED" || status === "CLOSED" ? new Date(NOW.getTime() - DAY) : null,
    closedAt: status === "CLOSED" ? new Date(NOW.getTime() - DAY) : null, closureSnapshot: null,
    createdBy: "u-admin", createdAt: new Date(NOW.getTime() - 5 * DAY), updatedAt: new Date(NOW),
  };
  w.stores.get("remediationCase")!.push(kase);
  return kase;
}


/* --------------------------------- tests --------------------------------- */

describe("case creation: ownership + SLA snapshot (§134)", () => {
  it("ensures one active case, resolves ownership, snapshots the SLA with policy version", async () => {
    const w = makeWorld({
      finding: [findingSeed({ assignedToId: "u-eng" })],
    });
    const { case: kase, created, slaAssigned } = await w.cases.ensureCase(admin, "ws-1", "f-1", NOW);
    expect(created).toBe(true);
    expect(slaAssigned).toBe(true);
    expect(kase.ownerId).toBe("u-eng");
    expect(kase.ownershipConfidence).toBe("VERIFIED");
    const snapshot = w.stores.get("remediationSlaSnapshot")![0]!;
    expect(snapshot.policyId).toBe("pol-1");
    expect(snapshot.policyVersion).toBe(3);
    expect((snapshot.dueAt as Date).getTime() - (snapshot.startedAt as Date).getTime()).toBe(72 * 3600 * 1000);
    const again = await w.cases.ensureCase(admin, "ws-1", "f-1", NOW);
    expect(again.created).toBe(false);
    expect(again.case.id).toBe(kase.id);
    expect(w.stores.get("remediationCase")).toHaveLength(1);
  });

  it("owner suggestion never assigns (§17)", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "NEW", { assignedToId: "u-eng" });
    const s = await w.ownership.suggestOwner("ws-1", "case-1");
    expect(s.assigned).toBe(false);
  });
});

describe("state machine guards (§133)", () => {
  it("rejects NEW → CLOSED and any direct jump to VERIFIED_FIXED", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "NEW");
    await expect(w.cases.transition(admin, "ws-1", "case-1", { to: "CLOSED" })).rejects.toThrow(/closure engine/);
    await expect(w.cases.transition(admin, "ws-1", "case-1", { to: "VERIFIED_FIXED" })).rejects.toThrow(/governed workflow/);
    await expect(w.closure.closeCase(admin, "ws-1", "case-1", { reason: "done" })).rejects.toThrow(/VERIFIED_FIXED/);
  });
});

describe("triage (§10–§13)", () => {
  it("false positive requires evidence; with evidence it moves case + finding", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "NEW");
    await expect(w.triage.triage(analyst, "ws-1", "case-1", { decision: "FALSE_POSITIVE", reason: "not exploitable" }))
      .rejects.toThrow(/evidence/);
    const { case: kase } = await w.triage.triage(analyst, "ws-1", "case-1", {
      decision: "FALSE_POSITIVE", reason: "compensating control verified", evidence: { ref: "waf-rule-7" },
    });
    expect(kase.status).toBe("FALSE_POSITIVE");
    expect(w.stores.get("finding")![0]!.lifecycleStatus).toBe("FALSE_POSITIVE");
  });

  it("duplicate triage parks the case against the canonical primary", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "TRIAGED");
    w.stores.get("finding")!.push(findingSeed({ id: "f-2", title: "canonical" }));
    const { case: kase } = await w.triage.triage(analyst, "ws-1", "case-1", {
      decision: "DUPLICATE", reason: "same CVE on same asset", canonicalFindingId: "f-2",
    });
    expect(kase.status).toBe("DEFERRED");
  });
});

describe("SLA pause + recalculation (§135/§25)", () => {
  it("denies unauthorized pause, invalid reasons and double pause; resume restores the clock", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    w.stores.get("remediationSlaSnapshot")!.push({
      id: "snap-1", caseId: "case-1", workspaceId: "ws-1", policyId: "pol-1", policyVersion: 3,
      inputs: {}, targetHours: 72, startedAt: new Date(NOW.getTime() - DAY), dueAt: new Date(NOW.getTime() + 2 * DAY),
      state: "ON_TRACK", pausedAt: null, pauseReason: null, pausedDurationMs: 0, completedAt: null,
      lastEvaluatedAt: null, createdAt: new Date(NOW), updatedAt: new Date(NOW),
    });
    await expect(w.sla.pauseSla(viewer, "ws-1", "case-1", { reason: "WAITING_VENDOR" })).rejects.toThrow(/PAUSE_REMEDIATION_SLA/);
    await expect(w.sla.pauseSla(admin, "ws-1", "case-1", { reason: "WHENEVER" })).rejects.toThrow(/one of/);
    await expect(w.sla.pauseSla(admin, "ws-1", "case-1", { reason: "APPROVED_EXCEPTION" })).rejects.toThrow(/approver/);
    await w.sla.pauseSla(admin, "ws-1", "case-1", { reason: "WAITING_VENDOR" }, NOW);
    expect(w.stores.get("remediationSlaSnapshot")![0]!.state).toBe("PAUSED");
    await expect(w.sla.pauseSla(admin, "ws-1", "case-1", { reason: "WAITING_VENDOR" })).rejects.toThrow(/already paused/);
    const resumed = await w.sla.resumeSla(admin, "ws-1", "case-1", new Date(NOW.getTime() + 2 * 3600 * 1000));
    expect(resumed.pausedDurationMs).toBe(2 * 3600 * 1000);
    expect(resumed.state).toBe("ON_TRACK");
  });

  it("recalculation never silently shortens (§25)", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    w.stores.get("remediationSlaSnapshot")!.push({
      id: "snap-1", caseId: "case-1", workspaceId: "ws-1", policyId: "pol-1", policyVersion: 3,
      inputs: {}, targetHours: 72, startedAt: new Date(NOW.getTime() - 5 * DAY), dueAt: new Date(NOW.getTime() + 2 * DAY),
      state: "ON_TRACK", pausedAt: null, pauseReason: null, pausedDurationMs: 0, completedAt: null,
      lastEvaluatedAt: null, createdAt: new Date(NOW), updatedAt: new Date(NOW),
    });
    const blocked = await w.sla.recalculate(admin, "ws-1", "case-1", {});
    expect(blocked.applied).toBe(false);
    expect(blocked.shortened).toBe(true);
    const allowed = await w.sla.recalculate(admin, "ws-1", "case-1", { allowShorten: true });
    expect(allowed.applied).toBe(true);
  });
});

describe("SLA breach tick with a controlled clock (§136)", () => {
  it("derives BREACHED and emits the event + notification route", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    w.stores.get("remediationSlaSnapshot")!.push({
      id: "snap-1", caseId: "case-1", workspaceId: "ws-1", policyId: "pol-1", policyVersion: 3,
      inputs: {}, targetHours: 72, startedAt: new Date(NOW.getTime() - 10 * DAY), dueAt: new Date(NOW.getTime() - DAY),
      state: "ON_TRACK", pausedAt: null, pauseReason: null, pausedDurationMs: 0, completedAt: null,
      lastEvaluatedAt: null, createdAt: new Date(NOW), updatedAt: new Date(NOW),
    });
    const result = await w.sla.evaluateWorkspace(admin, "ws-1", NOW);
    expect(result.changes).toEqual([{ caseId: "case-1", from: "ON_TRACK", to: "BREACHED" }]);
    expect(w.stores.get("remediationSlaSnapshot")![0]!.state).toBe("BREACHED");
    expect(w.published.some((e) => e.eventType === "REMEDIATION_SLA_BREACHED")).toBe(true);
  });
});

describe("tickets: failure, idempotency, sync (§130–§132/§148)", () => {
  it("unconfigured provider → work item FAILED with retry state; duplicate create returns the same item", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    const first = await w.tickets.createTicket(analyst, "ws-1", "case-1", { provider: "JIRA" }, NOW);
    expect(first.workItem.status).toBe("FAILED");
    expect(String(first.workItem.lastError)).toContain("NOT_CONFIGURED");
    expect(first.workItem.nextRetryAt).toBeTruthy();
    const dup = await w.tickets.createTicket(analyst, "ws-1", "case-1", { provider: "JIRA" }, NOW);
    expect(dup.duplicate).toBe(true);
    expect(dup.workItem.id).toBe(first.workItem.id);
    expect(w.stores.get("remediationWorkItem")).toHaveLength(1);
  });

  it("provider throw → FAILED, retry succeeds on the same work item (no duplicate ticket)", async () => {
    const provider = new FixtureTicketProvider();
    provider.failNext = true;
    const w = makeWorld({}, provider);
    await caseAtStatus(w, "IN_PROGRESS");
    const first = await w.tickets.createTicket(analyst, "ws-1", "case-1", { provider: "JIRA" }, NOW);
    expect(first.workItem.status).toBe("FAILED");
    const retried = await w.tickets.retryTicket(analyst, "ws-1", first.workItem.id, NOW);
    expect(retried.workItem.status).toBe("CREATED");
    expect(retried.workItem.id).toBe(first.workItem.id);
    expect(provider.tickets.size).toBe(1);
  });

  it("external ticket closed → FIX_CLAIMED via ticket sync, never VERIFIED_FIXED", async () => {
    const provider = new FixtureTicketProvider();
    const w = makeWorld({}, provider);
    await caseAtStatus(w, "IN_PROGRESS");
    const { workItem } = await w.tickets.createTicket(analyst, "ws-1", "case-1", { provider: "JIRA" }, NOW);
    provider.tickets.set(workItem.externalId!, { status: "DONE", closed: true });
    const synced = await w.tickets.syncWorkItem(analyst, "ws-1", workItem.id, NOW);
    expect(synced.synced).toBe(true);
    const kase = w.stores.get("remediationCase")![0]!;
    expect(kase.status).toBe("FIX_CLAIMED");
    expect(kase.status).not.toBe("VERIFIED_FIXED");
    const claim = w.stores.get("remediationFixClaim")![0]!;
    expect(claim.claimSource).toBe("TICKET_SYNC");
  });

  it("ticket payloads are secret-scrubbed (§148)", async () => {
    const provider = new FixtureTicketProvider();
    const w = makeWorld({}, provider);
    await caseAtStatus(w, "IN_PROGRESS", { title: "Config leak AKIAIOSFODNN7EXAMPLE exposed" });
    const { workItem } = await w.tickets.createTicket(analyst, "ws-1", "case-1", { provider: "JIRA" }, NOW);
    const payload = workItem.payload as { title: string; body: string; redactions: string[] };
    expect(payload.title).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(payload.body).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(payload.redactions.length).toBeGreaterThan(0);
  });
});

describe("fix claims (§137)", () => {
  it("a claim moves the case to FIX_CLAIMED and the finding only to REMEDIATED", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    const { case: kase } = await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", {
      claimSource: "MANUAL", description: "upgraded log4j to 2.17.1", commitRef: "abc123",
    });
    expect(kase.status).toBe("FIX_CLAIMED");
    const finding = w.stores.get("finding")![0]!;
    expect(finding.lifecycleStatus).toBe("REMEDIATED");
    expect(finding.lifecycleStatus).not.toBe("RESOLVED");
  });
});

describe("verification engine (§138–§142)", () => {
  async function claimedWorld() {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "fix applied" });
    return w;
  }

  it("rejects a method the category policy does not allow (§54)", async () => {
    const w = await claimedWorld();
    await expect(w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "SAFE_RESCAN" }))
      .rejects.toThrow(/not allowed/);
  });

  it("manual verification pass → VERIFIED_FIXED and the finding walks to RESOLVED", async () => {
    const w = await claimedWorld();
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    const result = await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: false, evidenceSufficient: true,
      beforeObservation: { version: "2.14.1" }, afterObservation: { version: "2.17.1" },
    });
    expect(result.evaluation.outcome).toBe("PASSED");
    expect(result.case.status).toBe("VERIFIED_FIXED");
    expect(w.stores.get("finding")![0]!.lifecycleStatus).toBe("RESOLVED");
    const closed = await w.closure.closeCase(engineer, "ws-1", "case-1", { reason: "verified and reviewed" });
    expect(closed.case.status).toBe("CLOSED");
    expect(closed.closureSnapshot.findingLifecycle).toBe("RESOLVED");
  });

  it("verification failure returns the case to actionable work (§139)", async () => {
    const w = await claimedWorld();
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    const result = await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: true, evidenceSufficient: true,
    });
    expect(result.evaluation.outcome).toBe("FAILED");
    expect(result.case.status).toBe("IN_PROGRESS");
  });

  it("scanner ERROR is never a pass (§140)", async () => {
    const w = await claimedWorld();
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    const result = await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "ERROR", stillPresent: false, evidenceSufficient: true,
    });
    expect(result.evaluation.outcome).toBe("ERROR");
    expect(result.case.status).toBe("VERIFICATION_PENDING");
    expect(w.stores.get("finding")![0]!.lifecycleStatus).not.toBe("RESOLVED");
  });

  it("insufficient evidence is INCONCLUSIVE and closes nothing (§141)", async () => {
    const w = await claimedWorld();
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    const result = await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: null, evidenceSufficient: false,
    });
    expect(result.evaluation.outcome).toBe("INCONCLUSIVE");
    expect(result.case.status).toBe("VERIFICATION_PENDING");
  });

  it("multi-observation confirmation requires N consecutive clean results (§142)", async () => {
    const w = makeWorld({ remediationSlaPolicy: [policySeed({ conditions: { requiredCleanObservations: 2 } })] });
    await caseAtStatus(w, "IN_PROGRESS");
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "fix applied" });
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    expect(job.requiredCleanObservations).toBe(2);
    const first = await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: false, evidenceSufficient: true,
    });
    expect(first.evaluation.outcome).toBe("PENDING_CONFIRMATION");
    expect(first.case.status).toBe("VERIFICATION_RUNNING");
    const second = await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: false, evidenceSufficient: true,
    });
    expect(second.evaluation.outcome).toBe("PASSED");
    expect(second.case.status).toBe("VERIFIED_FIXED");
  });

  it("SoD: the fix claimer cannot verify their own high-risk fix (§122)", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    await w.tickets.recordFixClaim(engineer, "ws-1", "case-1", { claimSource: "MANUAL", description: "fix applied" });
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    await expect(w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: false, evidenceSufficient: true,
    })).rejects.toThrow(/segregation of duties/);
  });

  it("retest-backed verification rides the governed P11 retest path (§55)", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS", { vulnClass: "web" });
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "fix applied" });
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "TARGETED_RETEST" });
    expect(w.retestCalls).toHaveLength(1);
    expect(job.retestRequestId).toBe("rt-1");
    expect(job.status).toBe("RUNNING");
  });

  it("a retest gate denial is recorded on the job, never bypassed (§55)", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS", { vulnClass: "web", gateDeny: true });
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "fix applied" });
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "TARGETED_RETEST" });
    expect(job.status).toBe("ERROR");
  });
});

describe("SBOM reevaluation (§153)", () => {
  it("still-AFFECTED fails; a clean match set passes on the next job", async () => {
    const w = makeWorld({
      softwareComponent: [{ id: "comp-1", name: "log4j-core", version: "2.14.1", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }],
      componentVulnerabilityMatch: [{ id: "m-1", workspaceId: "ws-1", componentId: "comp-1", cveId: "CVE-2021-44228", matchType: "EXACT", confidence: "HIGH", affectedStatus: "AFFECTED", evidence: {} }],
    });
    await caseAtStatus(w, "IN_PROGRESS");
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "bumped dependency" });
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "SBOM_REEVALUATION" });
    const failed = await w.verification.reevaluateSbom(engineer, "ws-1", "case-1", job.id);
    expect(failed.evaluation.outcome).toBe("FAILED");
    w.stores.get("componentVulnerabilityMatch")![0]!.affectedStatus = "NOT_AFFECTED";
    // A failed verification requires a NEW fix claim before retesting.
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "actually upgraded this time" });
    const { job: job2 } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "SBOM_REEVALUATION" });
    const passed = await w.verification.reevaluateSbom(engineer, "ws-1", "case-1", job2.id);
    expect(passed.evaluation.outcome).toBe("PASSED");
    expect(passed.case.status).toBe("VERIFIED_FIXED");
  });
});

describe("exceptions (§144–§146)", () => {
  it("enforces requirements, SoD approval, GRC linkage and expiry return-to-actionable", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "TRIAGED");
    await expect(w.exceptions.createException(analyst, "ws-1", "case-1", {
      type: "RISK_ACCEPTANCE", reason: "compensated by WAF", ownerId: "u-eng",
      expiresAt: new Date(NOW.getTime() + 30 * DAY),
    })).rejects.toThrow(/compensating controls/);
    await expect(w.exceptions.createException(analyst, "ws-1", "case-1", {
      type: "RISK_ACCEPTANCE", reason: "x", ownerId: "u-eng",
      expiresAt: new Date(NOW.getTime() - DAY), compensatingControls: ["waf"],
    })).rejects.toThrow(/future/);
    const exception = await w.exceptions.createException(analyst, "ws-1", "case-1", {
      type: "RISK_ACCEPTANCE", reason: "compensated by WAF", ownerId: "u-eng",
      expiresAt: new Date(NOW.getTime() + 30 * DAY), compensatingControls: ["waf-rule-7"],
    });
    expect(exception.riskExceptionId).toBeTruthy();
    expect(w.stores.get("riskException")).toHaveLength(1);
    // The requester cannot approve their own exception (§79 SoD) — use
    // a second requester who HOLDS the approve permission to isolate
    // the SoD rule from the permission rule.
    const own = await w.exceptions.createException(engineer, "ws-1", "case-1", {
      type: "TEMPORARY_DEFERRAL", reason: "vendor patch pending", ownerId: "u-eng",
      expiresAt: new Date(NOW.getTime() + 10 * DAY),
    });
    await expect(w.exceptions.approveException(engineer, "ws-1", "case-1", own.id))
      .rejects.toThrow(/segregation of duties/);
    await expect(w.exceptions.approveException(analyst, "ws-1", "case-1", exception.id))
      .rejects.toThrow(/APPROVE_REMEDIATION_EXCEPTION/);
    const approved = await w.exceptions.approveException(admin, "ws-1", "case-1", exception.id);
    expect(approved.case.status).toBe("ACCEPTED_RISK");
    expect(w.stores.get("riskException")![0]!.status).toBe("ACTIVE");
    expect(w.stores.get("finding")![0]!.lifecycleStatus).toBe("ACCEPTED_RISK");
    const sweep = await w.exceptions.sweepExpiries(admin, "ws-1", new Date(NOW.getTime() + 31 * DAY));
    expect(sweep.expired).toBe(1);
    const kase = w.stores.get("remediationCase")![0]!;
    expect(kase.status).toBe("TRIAGED");
    expect(w.published.some((e) => e.eventType === "REMEDIATION_EXCEPTION_EXPIRED")).toBe(true);
  });
});

describe("regressions (§143)", () => {
  it("a reappearing fingerprint reopens case + finding; a different fingerprint does not", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "CLOSED", { lifecycleStatus: "RESOLVED", resolvedAt: new Date(NOW.getTime() - DAY) });
    w.stores.get("finding")!.push(findingSeed({
      id: "f-obs", duplicateOfId: "f-1", lifecycleStatus: "NEW", lastSeen: new Date(NOW),
    }));
    const result = await w.regressions.detectRegressions(admin, "ws-1", NOW);
    expect(result.detected).toHaveLength(1);
    const kase = w.stores.get("remediationCase")![0]!;
    expect(kase.status).toBe("REOPENED");
    expect(kase.regressionCount).toBe(1);
    expect(w.stores.get("remediationRegressionEvent")).toHaveLength(1);
    expect(w.stores.get("finding")![0]!.lifecycleStatus).toBe("NEW");
    expect(w.published.some((e) => e.eventType === "VULNERABILITY_REGRESSION_DETECTED")).toBe(true);

    const w2 = makeWorld();
    await caseAtStatus(w2, "CLOSED", { lifecycleStatus: "RESOLVED", resolvedAt: new Date(NOW.getTime() - DAY) });
    w2.stores.get("finding")!.push(findingSeed({
      id: "f-obs", duplicateOfId: "f-1", fingerprint: "fp-different-bug", lifecycleStatus: "NEW", lastSeen: new Date(NOW),
    }));
    const none = await w2.regressions.detectRegressions(admin, "ws-1", NOW);
    expect(none.detected).toHaveLength(0);
    expect(w2.stores.get("remediationCase")![0]!.status).toBe("CLOSED");
  });
});

describe("bulk actions (§147)", () => {
  it("bulk VERIFIED_FIXED/CLOSED is rejected; assignment needs preview + confirmation", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "TRIAGED");
    await expect(w.bulk.bulk(admin, "ws-1", { action: "CLOSE", caseIds: ["case-1"], confirm: true }))
      .rejects.toThrow(/not permitted/);
    const preview = await w.bulk.bulk(admin, "ws-1", { action: "ASSIGN", caseIds: ["case-1"], ownerType: "TEAM", teamId: "team-9" });
    expect(preview.requiresConfirmation).toBe(true);
    expect(w.stores.get("remediationCase")![0]!.teamId).toBeNull();
    const applied = await w.bulk.bulk(admin, "ws-1", { action: "ASSIGN", caseIds: ["case-1"], ownerType: "TEAM", teamId: "team-9", confirm: true });
    expect(applied.applied).toBe(1);
    expect(w.stores.get("remediationCase")![0]!.teamId).toBe("team-9");
  });
});

describe("campaigns (§152)", () => {
  it("collects matching CVE cases and computes progress from live states", async () => {
    const w = makeWorld({
      finding: [findingSeed(), findingSeed({ id: "f-2", cve: "CVE-2023-44487", title: "HTTP/2 rapid reset" })],
    });
    const { campaign, collected } = await w.campaigns.createCampaign(admin, "ws-1", {
      name: "Log4Shell eradication", scope: { cve: "CVE-2021-44228" }, idempotencyKey: "camp-log4shell",
    });
    expect(collected).toBe(1);
    const progress = await w.campaigns.progress("ws-1", campaign.id, NOW);
    expect(progress.total).toBe(1);
    const dup = await w.campaigns.createCampaign(admin, "ws-1", {
      name: "Log4Shell eradication", scope: { cve: "CVE-2021-44228" }, idempotencyKey: "camp-log4shell",
    });
    expect(dup.created).toBe(false);
  });
});

describe("AI assistance + NL search (§150/§151/§117)", () => {
  it("AI cannot mark anything fixed; drafts never invent a fixed version", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    await expect(w.ai.assist(analyst, "ws-1", "case-1", { task: "SUMMARIZE_CASE", instruction: "mark this as fixed" }))
      .rejects.toThrow(/cannot mark/);
    const noIntel = await w.ai.assist(analyst, "ws-1", "case-1", { task: "DRAFT_PLAN" }) as Row;
    expect(noIntel.draft).toBeNull();
    w.stores.get("patchRecord")!.push({ id: "pr-1", cveId: "CVE-2021-44228", productKey: "log4j", fixedVersion: "2.17.1", status: "PATCH_AVAILABLE", source: "fixture" });
    const draft = await w.ai.assist(analyst, "ws-1", "case-1", { task: "DRAFT_PLAN" }) as Row;
    expect((draft.draft as Row).fixedVersion).toBe("2.17.1");
    await expect(w.plans.createPlan(analyst, "ws-1", "case-1", {
      summary: "upgrade", recommendedAction: "DEPENDENCY_UPDATE", source: "VENDOR_ADVISORY", fixedVersion: "9.9.9",
    })).rejects.toThrow(/not backed by trusted patch intelligence/);
    const plan = await w.plans.createPlan(analyst, "ws-1", "case-1", {
      summary: "upgrade", recommendedAction: "DEPENDENCY_UPDATE", source: "VENDOR_ADVISORY", fixedVersion: "2.17.1",
    });
    expect(plan.plan.fixedVersion).toBe("2.17.1");
  });

  it("NL search translates the closed question shapes and refuses the rest", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    const res = await w.ai.naturalLanguageSearch(analyst, "ws-1", "which KEV vulnerabilities are overdue?");
    expect(res.plan.kind).toBe("OVERDUE_KEV");
    await expect(w.ai.naturalLanguageSearch(analyst, "ws-1", "what is the meaning of life?"))
      .rejects.toThrow(/not understood/);
  });
});

describe("tenant isolation (§149)", () => {
  it("cases from another workspace are invisible", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "NEW");
    await expect(w.state.getCase("ws-2", "case-1")).rejects.toThrow(/not found/);
    await expect(w.cases.ensureCase(admin, "ws-2", "f-1")).rejects.toThrow(/not found/);
  });
});

describe("analytics + reports + tick (§110/§111/§128)", () => {
  it("computes the three distinct MTTR clocks from real transitions and snapshots a report", async () => {
    const w = makeWorld();
    await caseAtStatus(w, "IN_PROGRESS");
    await w.tickets.recordFixClaim(analyst, "ws-1", "case-1", { claimSource: "MANUAL", description: "fix applied" });
    const { job } = await w.verification.requestVerification(analyst, "ws-1", "case-1", { method: "MANUAL_EVIDENCE_REVIEW" });
    await w.verification.recordObservation(engineer, "ws-1", "case-1", job.id, {
      scannerStatus: "OK", stillPresent: false, evidenceSufficient: true,
    });
    await w.closure.closeCase(engineer, "ws-1", "case-1", { reason: "verified" });
    const metrics = await w.analytics.metrics("ws-1", {}, NOW);
    expect(metrics.openBacklog).toBe(0);
    expect(metrics.meanTimeToClaimFixHours).not.toBeNull();
    expect(metrics.meanTimeToVerifyFixHours).not.toBeNull();
    expect(metrics.meanTimeToCloseHours).not.toBeNull();
    const report = await w.reports.generate(admin, "ws-1", { type: "REMEDIATION_STATUS" }, NOW);
    expect(String(report.contentHash)).toHaveLength(64);
    const tickResult = await w.tick.tick(admin, "ws-1", NOW);
    expect(tickResult.sla.evaluated).toBeGreaterThanOrEqual(0);
  });
});
