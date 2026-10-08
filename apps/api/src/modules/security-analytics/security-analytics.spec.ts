import { AnalyticsStoreService } from "./storage/analytics-store.service";
import { IngestionService } from "./ingestion/ingestion.service";
import { IndexingService } from "./search/indexing.service";
import { SearchService } from "./search/search.service";
import { AggregationService } from "./aggregations/aggregation.service";
import { AttackSurfaceService } from "./attack-surface/attack-surface.service";
import { TimelineService } from "./timelines/timeline.service";
import { CorrelationService } from "./correlation/correlation.service";
import { GraphService } from "./graph/graph.service";
import { SavedQueryService } from "./saved-queries/saved-query.service";
import { ExportService } from "./exports/export.service";
import { AiAnalyticsService } from "./ai/ai-analytics.service";
import { RetentionService } from "./retention/retention.service";
import { AnalyticsHealthService } from "./health/health.service";
import { AnalyticsCacheService } from "./cache";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (same pattern as prior phase specs).          */
/* ------------------------------------------------------------------ */

function mockFn(impl: (...args: never[]) => Promise<unknown>) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => { calls.push(args); return impl(...(args as never[])); };
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
function makeTable(name: string) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      for (const f of ["ingestedAt", "capturedAt", "recordedAt", "detectedAt", "firstSeenAt", "lastSeenAt", "collectedAt", "evaluatedAt"]) {
        if (row[f] === undefined) row[f] = stamp;
      }
      rows.push(row);
      return row;
    },
    async createMany({ data }: { data: Row[] }) { for (const d of data) await table.create({ data: d }); return { count: data.length }; },
    async findUnique({ where }: { where: Record<string, unknown> }) { return rows.find((r) => matches(r, where)) ?? null; },
    async findFirst(args: { where?: Record<string, unknown>; orderBy?: Record<string, string> } = {}) {
      const list = await table.findMany({ ...args, take: 1 }); return list[0] ?? null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number; skip?: number; orderBy?: Record<string, string> | Array<Record<string, string>> } = {}) {
      let out = rows.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy[0] : args.orderBy;
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0]!;
        out = [...out].sort((a, b) => cmp(a[field], b[field]) * (dir === "desc" ? -1 : 1));
      }
      if (args.skip) out = out.slice(args.skip);
      if (args.take) out = out.slice(0, args.take);
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
    async deleteMany({ where }: { where?: Record<string, unknown> } = {}) {
      let count = 0;
      for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i]!, where)) { rows.splice(i, 1); count++; }
      return { count };
    },
    async count(args: { where?: Record<string, unknown> } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
  };
  return table;
}

const TABLES = [
  "workspace", "auditLog", "securityAnalyticsEvent", "analyticsIngestionCheckpoint", "analyticsDeadLetterEvent",
  "securitySearchDocument", "savedSecurityQuery", "assetSecuritySnapshot", "findingLifecycleProjection",
  "riskHistoryProjection", "exposureSnapshot", "shadowAssetSignal", "correlationRule", "securityCorrelationSignal",
  "attackPathCandidate", "analyticsRetentionPolicy", "securitySearchReindexJob", "analyticsDashboardSnapshot",
  "securityEventOutbox", "findingHistory", "finding", "asset", "service", "technology", "scan",
  "securityPostureSnapshot", "qualityGateResult", "sourceRepository", "securityReport", "securityControl",
  "riskRecord", "remediationTicket", "membership", "mfaMethod", "enterpriseSsoProvider", "apiKey",
  "serviceAccount", "accessReview", "controlEvaluation", "complianceEvidence", "evidenceFreshnessPolicy",
  "riskAcceptance", "auditFinding", "complianceFramework", "complianceAssessment", "kubernetesWorkload",
  "containerImage", "assetSnapshot", "assetSnapshotEntry",
] as const;

function makeFake() {
  const db: Record<string, ReturnType<typeof makeTable>> = {};
  for (const t of TABLES) db[t] = makeTable(t);
  return db;
}

/* ------------------------------------------------------------------ */

const OWNER: RequestUser = { id: "u-owner", email: "rudra@example.com", organizationId: "org-1", role: "OWNER" };
const ENGINEER: RequestUser = { id: "u-eng", email: "eng@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" };
const ANALYST: RequestUser = { id: "u-analyst", email: "analyst@example.com", organizationId: "org-1", role: "ANALYST" };
const VIEWER: RequestUser = { id: "u-viewer", email: "viewer@example.com", organizationId: "org-1", role: "VIEWER" };
const OTHER_ORG: RequestUser = { id: "u-other", email: "other@example.com", organizationId: "org-2", role: "OWNER" };
const WS = { id: "ws-1" };
const WS2 = { id: "ws-2" };
const SCOPE = { organizationId: "org-1", workspaceId: "ws-1" };

function makeStack() {
  const prisma = makeFake();
  const audit = { record: mockFn(async () => ({})) };
  const store = new AnalyticsStoreService(prisma as never);
  const ingestion = new IngestionService(prisma as never, store);
  const indexing = new IndexingService(prisma as never);
  const search = new SearchService(prisma as never, audit as never);
  const attackSurface = new AttackSurfaceService(prisma as never);
  const aggregations = new AggregationService(prisma as never, attackSurface);
  const timelines = new TimelineService(prisma as never, store);
  const correlations = new CorrelationService(prisma as never);
  const graph = new GraphService(prisma as never);
  const savedQueries = new SavedQueryService(prisma as never, search);
  const exportsSvc = new ExportService(prisma as never, audit as never, search, aggregations);
  const ai = new AiAnalyticsService(prisma as never, search, graph);
  const retention = new RetentionService(prisma as never, indexing, ingestion, store);
  const health = new AnalyticsHealthService(prisma as never);
  const cache = new AnalyticsCacheService();
  return { prisma, audit, store, ingestion, indexing, search, attackSurface, aggregations, timelines, correlations, graph, savedQueries, exportsSvc, ai, retention, health, cache };
}

async function seedWorkspaces(s: ReturnType<typeof makeStack>) {
  await s.prisma.workspace.create({ data: { id: "ws-1", organizationId: "org-1", deletedAt: null } as never });
  await s.prisma.workspace.create({ data: { id: "ws-2", organizationId: "org-2", deletedAt: null } as never });
}

let findingSeq = 0;
function findingRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  findingSeq++;
  return {
    id: `f-${findingSeq}`, workspaceId: "ws-1", scanId: "scan-1", assetId: null,
    title: `Finding ${findingSeq}`, description: "desc", severity: "HIGH", confidence: 0.8,
    cvssScore: null, cve: null, cwe: null, status: "OPEN", verificationStatus: "UNVERIFIED",
    sources: [], riskScore: 70, lifecycleStatus: "NEW", priority: "P1", kevListed: false,
    epssScore: null, tags: [], dueAt: null, resolvedAt: null, reopenedAt: null, recurrenceCount: 0,
    repositoryId: null, sourceDomain: "WEB", category: "VULNERABILITY", dataSensitivity: null,
    environment: null, cloudProvider: null, cloudAccountId: null, findingClass: null,
    imageDigest: null, imageRef: null, clusterRef: null, host: null, vulnClass: null, remediation: "fix it",
    ...overrides,
  };
}

function eventRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    eventId: `evt-${Math.random().toString(36).slice(2, 10)}`, organizationId: "org-1", workspaceId: "ws-1",
    eventType: "FINDING_CREATED", eventTime: "2026-10-01T00:00:00.000Z", sourceType: "FIXTURE",
    resourceType: "FINDING", resourceId: "f-1", findingId: "f-1", severity: "HIGH", riskScore: 70,
    classification: "INTERNAL", attributes: {},
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */

describe("ingestion (§8–§13)", () => {
  it("§131: the same eventId ingested twice produces ONE logical event", async () => {
    const s = makeStack();
    const ev = eventRow({ eventId: "evt-dup" });
    const first = await s.ingestion.ingestBatch(SCOPE, [ev]);
    const second = await s.ingestion.ingestBatch(SCOPE, [ev]);
    expect(first.stored).toBe(1);
    expect(second.stored).toBe(0);
    expect(second.duplicates).toBe(1);
    expect(await s.prisma.securityAnalyticsEvent.count({ where: { workspaceId: "ws-1" } })).toBe(1);
  });

  it("invalid events are quarantined in the dead-letter, never silently dropped (§11/§12)", async () => {
    const s = makeStack();
    const out = await s.ingestion.ingestBatch(SCOPE, [eventRow({ eventType: "NOT_A_TYPE" }), eventRow({ workspaceId: "ws-2" })]);
    expect(out.rejected).toBe(2);
    const dlq = await s.prisma.analyticsDeadLetterEvent.findMany({});
    expect(dlq.length).toBe(2);
    expect(JSON.stringify(dlq.map((d) => d.errors))).toContain("EVENT_TYPE_UNKNOWN");
    expect(JSON.stringify(dlq.map((d) => d.errors))).toContain("TENANT_CONTEXT_MISMATCH");
  });

  it("outbox consumption is checkpointed and idempotent (§8/§10)", async () => {
    const s = makeStack();
    await s.prisma.securityEventOutbox.create({ data: {
      id: "ob-1", workspaceId: "ws-1", eventId: "ob-evt-1", eventType: "FINDING_CREATED",
      resourceType: "FINDING", resourceId: "f-1", payload: { severity: "HIGH" }, status: "DELIVERED",
    } as never });
    const first = await s.ingestion.consumeOutbox(SCOPE);
    expect(first.stored).toBe(1);
    const second = await s.ingestion.consumeOutbox(SCOPE);
    expect(second.stored).toBe(0);
    const checkpoint = await s.prisma.analyticsIngestionCheckpoint.findFirst({ where: { workspaceId: "ws-1", partition: "OUTBOX" } });
    expect(checkpoint?.processed).toBeGreaterThanOrEqual(1);
  });

  it("§134: finding history projects a full lifecycle — create → verify → resolve → reopen", async () => {
    const s = makeStack();
    await s.prisma.finding.create({ data: findingRow({ id: "f-life", severity: "CRITICAL", lifecycleStatus: "REOPENED", cwe: "CWE-89" }) as never });
    const history: Array<[string, string]> = [
      ["CREATED", "2026-10-01T00:00:00.000Z"], ["CONFIRMED", "2026-10-02T00:00:00.000Z"],
      ["RESOLVED", "2026-10-05T00:00:00.000Z"], ["REOPENED", "2026-10-07T00:00:00.000Z"],
    ];
    for (const [i, [event, at]] of history.entries()) {
      await s.prisma.findingHistory.create({ data: {
        id: `h-${i}`, findingId: "f-life", workspaceId: "ws-1", event, createdAt: new Date(at),
      } as never });
    }
    const outcome = await s.ingestion.consumeFindingHistory(SCOPE);
    expect(outcome.stored).toBe(4);
    const projection = await s.prisma.findingLifecycleProjection.findFirst({ where: { workspaceId: "ws-1", findingId: "f-life" } });
    expect(projection).not.toBeNull();
    expect(projection!.remediationSeconds).toBe(4 * 86_400);
    expect(projection!.regressionCount).toBe(1);
    expect(projection!.verifiedAt).toEqual(new Date("2026-10-02T00:00:00.000Z"));
    // §132/§99: the timeline is ordered by eventTime.
    const timeline = await s.timelines.findingTimeline(SCOPE, "f-life");
    expect(timeline.events.map((e) => e.eventType)).toEqual(["FINDING_CREATED", "FINDING_VERIFIED", "FINDING_RESOLVED", "FINDING_REOPENED"]);
  });

  it("§133: rebuilding projections from history reproduces the same projection", async () => {
    const s = makeStack();
    await s.ingestion.ingestBatch(SCOPE, [
      eventRow({ eventId: "r-1", eventType: "FINDING_CREATED", eventTime: "2026-10-01T00:00:00.000Z" }),
      eventRow({ eventId: "r-2", eventType: "FINDING_RESOLVED", eventTime: "2026-10-04T00:00:00.000Z" }),
    ]);
    const before = await s.prisma.findingLifecycleProjection.findFirst({ where: { findingId: "f-1" } });
    const result = await s.retention.rebuild(SCOPE);
    expect(result.findings).toBe(1);
    const after = await s.prisma.findingLifecycleProjection.findFirst({ where: { findingId: "f-1" } });
    expect(after!.remediationSeconds).toBe(before!.remediationSeconds);
    expect(after!.remediationSeconds).toBe(3 * 86_400);
  });

  it("§145: load — 10,000 events land + aggregate within a bounded time", async () => {
    const s = makeStack();
    // §145 measures the store path (idempotent insert + scoped
    // aggregate). Projection fan-out is covered by the lifecycle
    // tests; here all events share one finding so per-batch
    // reprojection stays O(1) and the measurement isolates landing.
    const events = Array.from({ length: 10_000 }, (_, i) => eventRow({
      eventId: `load-${i}`, resourceId: "f-load", findingId: "f-load",
      eventTime: new Date(Date.UTC(2026, 8, 1 + (i % 28))).toISOString(),
    }));
    const started = Date.now();
    let stored = 0;
    for (let i = 0; i < events.length; i += 500) {
      const out = await s.ingestion.ingestBatch(SCOPE, events.slice(i, i + 500));
      stored += out.stored;
    }
    const elapsedMs = Date.now() - started;
    expect(stored).toBe(10_000);
    const agg = await s.store.aggregate(SCOPE, ["FINDING_CREATED"]);
    expect(agg.total).toBe(10_000);
    // Measured, not claimed (§145): the bound is generous for the
    // in-memory fake (linear scans); production uses indexed INSERTs.
    expect(elapsedMs).toBeLessThan(120_000);
  }, 180_000);
});

describe("enterprise search (§19–§31)", () => {
  async function seedDocs(s: ReturnType<typeof makeStack>) {
    await s.prisma.securitySearchDocument.create({ data: {
      id: "doc-a", organizationId: "org-1", workspaceId: "ws-1", documentType: "ASSET", resourceId: "a-1",
      title: "prod-web-01", summary: "HOST", searchableText: "prod-web-01 wordpress host",
      facets: { assetHost: "prod-web-01", technologies: ["WordPress"], internetExposed: true, criticality: "CRITICAL" },
      classification: "INTERNAL", riskScore: 88, severity: null,
    } as never });
    await s.prisma.securitySearchDocument.create({ data: {
      id: "doc-secret", organizationId: "org-1", workspaceId: "ws-1", documentType: "FINDING", resourceId: "f-secret",
      title: "Restricted evidence bundle", summary: "RESTRICTED", searchableText: "restricted evidence bundle classifieddoc",
      facets: { severity: "CRITICAL" }, classification: "RESTRICTED", riskScore: 95, severity: "CRITICAL",
    } as never });
    await s.prisma.securitySearchDocument.create({ data: {
      id: "doc-b", organizationId: "org-2", workspaceId: "ws-2", documentType: "ASSET", resourceId: "a-9",
      title: "tenant-b-only-host", summary: "HOST", searchableText: "tenant-b-only-host",
      facets: { assetHost: "tenant-b-only-host" }, classification: "INTERNAL", riskScore: 10, severity: null,
    } as never });
  }

  it("§127: cross-tenant search returns nothing and suggestions never leak", async () => {
    const s = makeStack();
    await seedDocs(s);
    const result = await s.search.search(OWNER, WS, { query: "tenant-b-only-host" });
    expect(result.total).toBe(0);
    const suggestions = await s.search.suggestions(OWNER, WS, "tenant-b");
    expect(suggestions.suggestions).toEqual([]);
    const own = await s.search.search(OTHER_ORG, WS2, { query: "tenant-b-only-host" });
    expect(own.total).toBe(1);
  });

  it("§128: restricted content is absent for users without the restricted permission", async () => {
    const s = makeStack();
    await seedDocs(s);
    const viewerResult = await s.search.search(VIEWER, WS, { query: "classifieddoc" });
    expect(viewerResult.total).toBe(0);
    const engineerResult = await s.search.search(ENGINEER, WS, { query: "classifieddoc" });
    expect(engineerResult.total).toBe(1);
  });

  it("§34/§35: DSL search filters by typed fields; hostile text is inert data (§125)", async () => {
    const s = makeStack();
    await seedDocs(s);
    const dsl = await s.search.search(ENGINEER, WS, { query: "severity:critical" });
    expect(dsl.interpretedAs).toBe("DSL");
    expect(dsl.results.map((r) => r.resourceId)).toEqual(["f-secret"]);
    const hostile = await s.search.search(ENGINEER, WS, { query: "' OR '1'='1 -- DROP TABLE findings" });
    expect(hostile.total).toBe(0);
  });

  it("§129: snippets escape indexed HTML/script", async () => {
    const s = makeStack();
    await s.prisma.securitySearchDocument.create({ data: {
      id: "doc-xss", organizationId: "org-1", workspaceId: "ws-1", documentType: "FINDING", resourceId: "f-xss",
      title: `<script>alert(1)</script> xssprobe`, summary: "x", searchableText: "xssprobe finding",
      facets: {}, classification: "INTERNAL", riskScore: 10, severity: "LOW",
    } as never });
    const result = await s.search.search(ANALYST, WS, { query: "xssprobe" });
    expect(result.total).toBe(1);
    expect(result.results[0]!.snippet).not.toContain("<script>");
    expect(result.results[0]!.snippet).toContain("&lt;script&gt;");
  });

  it("§130: indexing redacts secrets out of searchable text", async () => {
    const s = makeStack();
    await s.prisma.finding.create({ data: findingRow({
      id: "f-leak", description: "evidence contains AKIAIOSFODNN7EXAMPLE in the dump",
    }) as never });
    await s.indexing.indexWorkspace(SCOPE);
    const docs = await s.prisma.securitySearchDocument.findMany({ where: { workspaceId: "ws-1", documentType: "FINDING" } });
    expect(docs.length).toBe(1);
    expect(docs[0]!.searchableText).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("facets + grouping + cursor pagination (§29/§30/§96)", async () => {
    const s = makeStack();
    await seedDocs(s);
    const result = await s.search.search(ENGINEER, WS, { query: "", pageSize: 1, group: true });
    expect(result.total).toBe(2);
    expect(result.results.length).toBe(1);
    expect(result.nextCursor).toBeTruthy();
    expect(result.facets.documentType?.length).toBeGreaterThan(0);
    expect(result.groupCounts).toEqual({ ASSET: 1, FINDING: 1 });
    const page2 = await s.search.search(ENGINEER, WS, { query: "", pageSize: 1, cursor: result.nextCursor! });
    expect(page2.results.length).toBe(1);
    expect(page2.results[0]!.documentId).not.toBe(result.results[0]!.documentId);
  });
});

describe("saved queries (§32/§33)", () => {
  it("private queries are owner-only; workspace queries are shared; stored DSL re-validates", async () => {
    const s = makeStack();
    const mine = await s.savedQueries.create(ANALYST, "ws-1", { name: "crit", queryText: "severity:critical", visibility: "PRIVATE" });
    expect(mine.id).toBeTruthy();
    const analystList = await s.savedQueries.list(ANALYST, "ws-1");
    const viewerList = await s.savedQueries.list(VIEWER, "ws-1");
    expect(analystList.length).toBe(1);
    expect(viewerList.length).toBe(0);
    await expect(s.savedQueries.create(ANALYST, "ws-1", { name: "bad", queryText: "bogus_field:1" })).rejects.toThrow();
  });
});

describe("attack surface intelligence (§51–§55, §135)", () => {
  it("snapshot + growth come from real inventory; shadow signals are evidence-only", async () => {
    const s = makeStack();
    await s.prisma.asset.create({ data: {
      id: "a-pub", workspaceId: "ws-1", targetId: "t-1", host: "203.0.113.10", ip: "203.0.113.10",
      type: "HOST", scopeStatus: "IN_SCOPE", sources: [], criticality: "UNSPECIFIED",
    } as never });
    await s.prisma.asset.create({ data: {
      id: "a-priv", workspaceId: "ws-1", targetId: "t-1", host: "db.internal", ip: "10.0.0.5",
      type: "HOST", scopeStatus: "IN_SCOPE", sources: [], criticality: "HIGH",
    } as never });
    await s.prisma.service.create({ data: { id: "svc-1", assetId: "a-pub", port: 443, protocol: "tcp", name: "https", state: "OPEN", tls: true, sources: [] } as never });
    const snap = await s.attackSurface.captureSnapshot("ws-1");
    expect(snap.totalAssets).toBe(2);
    expect(snap.internetFacingAssets).toBe(1);
    const dashboard = await s.attackSurface.dashboard("ws-1");
    expect(dashboard.services.open).toBe(1);
    expect(dashboard.certificates.tlsServices).toBe(1);
    // The unspecified public asset raises a shadow SIGNAL (not a verdict).
    const signals = await s.prisma.shadowAssetSignal.findMany({ where: { workspaceId: "ws-1" } });
    expect(signals.length).toBe(1);
    expect(signals[0]!.signalType).toBe("UNEXPECTED_SUBDOMAIN");
    const growth = await s.attackSurface.growth("ws-1");
    expect(growth.netGrowth).toBeNull(); // one snapshot — honest, not invented
  });
});

describe("correlation + graph + attack paths (§73–§87)", () => {
  async function seedRisky(s: ReturnType<typeof makeStack>) {
    await s.prisma.asset.create({ data: {
      id: "a-web", workspaceId: "ws-1", targetId: "t-1", host: "shop.example.com", ip: "203.0.113.20",
      type: "HOST", scopeStatus: "IN_SCOPE", sources: [], criticality: "CRITICAL", network: "203.0.113.0/24",
    } as never });
    await s.prisma.asset.create({ data: {
      id: "a-db", workspaceId: "ws-1", targetId: "t-1", host: "db.internal", ip: "203.0.113.21",
      type: "HOST", scopeStatus: "IN_SCOPE", sources: [], criticality: "HIGH", network: "203.0.113.0/24",
    } as never });
    await s.prisma.finding.create({ data: findingRow({
      id: "f-kev", assetId: "a-web", severity: "CRITICAL", verificationStatus: "CONFIRMED",
      kevListed: true, cve: "CVE-2021-44228", riskScore: 96, lifecycleStatus: "CONFIRMED",
    }) as never });
    await s.prisma.finding.create({ data: findingRow({
      id: "f-sensitive", assetId: "a-db", severity: "MEDIUM", dataSensitivity: "RESTRICTED",
    }) as never });
  }

  it("§136/§137: KEV + critical-asset signals are created once, then updated (§78)", async () => {
    const s = makeStack();
    await seedRisky(s);
    const first = await s.correlations.runCorrelations("ws-1");
    expect(first.created).toBeGreaterThanOrEqual(2);
    const signals = await s.prisma.securityCorrelationSignal.findMany({ where: { workspaceId: "ws-1" } });
    const types = signals.map((x) => x.signalType);
    expect(types).toContain("INTERNET_EXPOSED_KEV");
    expect(types).toContain("CRITICAL_ASSET_CRITICAL_FINDING");
    const kev = signals.find((x) => x.signalType === "INTERNET_EXPOSED_KEV")!;
    expect(kev.confidence).toBe("HIGH");
    const second = await s.correlations.runCorrelations("ws-1");
    expect(second.created).toBe(0);
    expect(second.updated).toBeGreaterThanOrEqual(2);
    const after = await s.prisma.securityCorrelationSignal.findFirst({ where: { id: kev.id } });
    expect(after!.occurrenceCount).toBe(2);
  });

  it("§138: attack path candidate chains internet → asset → finding → sensitive backend with evidence", async () => {
    const s = makeStack();
    await seedRisky(s);
    const gen = await s.graph.generateAttackPaths("ws-1");
    expect(gen.total).toBe(1);
    const paths = await s.graph.listAttackPaths("ws-1");
    const path = paths.items[0]!;
    expect(path.score).toBeGreaterThan(70);
    expect((path.edges as Array<{ evidenceId: string }>).every((e) => e.evidenceId)).toBe(true);
    expect((path.nodes as Array<{ kind: string }>).map((n) => n.kind)).toEqual(["INTERNET", "ASSET", "FINDING", "ASSET"]);
  });

  it("§139: excessive graph depth is bounded/rejected", async () => {
    const s = makeStack();
    await seedRisky(s);
    const ok = await s.graph.traverse("ws-1", "internet", { maxDepth: 2 });
    expect("rejected" in ok).toBe(false);
    const bad = await s.graph.traverse("ws-1", "internet", { maxDepth: 42 });
    expect("rejected" in bad && bad.rejected).toBeTruthy();
  });
});

describe("analytics aggregations (§39–§72)", () => {
  it("findings analytics: MTTR/SLA/regression computed from projections, empty stays empty", async () => {
    const s = makeStack();
    const empty = await s.aggregations.findingsAnalytics("ws-1");
    expect(empty.total).toBe(0);
    expect(empty.mttrBySeverity).toEqual([]);
    await s.prisma.finding.create({ data: findingRow({
      id: "f-mttr", severity: "HIGH", dueAt: new Date(Date.now() + 30 * 86_400_000), lifecycleStatus: "RESOLVED",
      resolvedAt: new Date(), cwe: "CWE-89", cve: "CVE-2024-0001", kevListed: true,
    }) as never });
    await s.prisma.findingLifecycleProjection.create({ data: {
      id: "p-1", workspaceId: "ws-1", findingId: "f-mttr",
      firstSeenAt: new Date("2026-10-01T00:00:00Z"), lastSeenAt: new Date("2026-10-03T00:00:00Z"),
      resolvedAt: new Date("2026-10-03T00:00:00Z"), regressionCount: 1, remediationSeconds: 172_800,
      currentStatus: "RESOLVED", severity: "HIGH", cwe: "CWE-89", cve: "CVE-2024-0001", assetId: null, repositoryId: null,
    } as never });
    const out = await s.aggregations.findingsAnalytics("ws-1");
    expect(out.mttrBySeverity).toEqual([{ key: "HIGH", resolvedCount: 1, unresolvedCount: 0, meanSeconds: 172_800, medianSeconds: 172_800 }]);
    expect(out.regressionRanking.length).toBe(1);
    expect(out.topCwes).toEqual([{ key: "CWE-89", count: 1 }]);
    expect(out.kev.listed).toBe(1);
  });

  it("identity analytics computes MFA coverage from real membership records", async () => {
    const s = makeStack();
    await s.prisma.membership.create({ data: { id: "m-1", userId: "u-1", organizationId: "org-1", role: "OWNER", status: "ACTIVE" } as never });
    await s.prisma.membership.create({ data: { id: "m-2", userId: "u-2", organizationId: "org-1", role: "ANALYST", status: "ACTIVE" } as never });
    await s.prisma.mfaMethod.create({ data: { id: "mfa-1", userId: "u-1", type: "TOTP", isActive: true } as never });
    const out = await s.aggregations.identityAnalytics(OWNER, "ws-1");
    expect(out.members).toBe(2);
    expect(out.mfaCoverage).toBe(0.5);
    expect(out.privilegedWithoutMfa).toBe(0);
  });

  it("overview names its sources and never fabricates a trend for empty data", async () => {
    const s = makeStack();
    const out = await s.aggregations.overview("ws-1");
    expect(out.sources.length).toBeGreaterThan(0);
    expect(out.findingTrend.every((p) => p.count === 0)).toBe(true);
    expect(out.mttr.meanSeconds).toBeNull();
    expect(out.regressionRate).toBeNull();
  });
});

describe("AI analytics (§104–§109)", () => {
  it("§108: NL question becomes governed DSL executed through authorized search", async () => {
    const s = makeStack();
    await s.prisma.securitySearchDocument.create({ data: {
      id: "doc-wp", organizationId: "org-1", workspaceId: "ws-1", documentType: "FINDING", resourceId: "f-wp",
      title: "WordPress RCE", summary: "critical", searchableText: "wordpress rce critical public",
      facets: { severity: "CRITICAL", technologies: ["WordPress"], internetExposed: true },
      classification: "INTERNAL", riskScore: 97, severity: "CRITICAL",
    } as never });
    const out = await s.ai.ask(ENGINEER, WS, "critical public WordPress findings");
    expect(out.status).toBe("OK");
    expect(out.dsl).toContain("technology:wordpress");
    expect(out.citations.length).toBe(1);
    const sql = await s.ai.ask(ENGINEER, WS, "'; DROP TABLE findings; --");
    expect(sql.status).toBe("INSUFFICIENT_EVIDENCE");
  });

  it("§140/§141: trend answers use deterministic metrics or say INSUFFICIENT_DATA", async () => {
    const s = makeStack();
    const empty = await s.ai.trend(ENGINEER, WS, "How much did critical exposure increase?");
    expect(empty.status).toBe("INSUFFICIENT_DATA");
    for (let i = 0; i < 3; i++) {
      await s.ingestion.ingestBatch(SCOPE, [eventRow({
        eventId: `t-${i}`, eventType: "FINDING_CREATED", severity: "CRITICAL",
        eventTime: new Date(Date.now() - i * 86_400_000).toISOString(),
      })]);
    }
    const ok = await s.ai.trend(ENGINEER, WS, "How much did critical exposure increase?");
    expect(ok.status).toBe("OK");
    expect(ok.text).toContain("Critical findings created");
  });
});

describe("exports, cache, retention, reindex, health (§102/§122/§143/§144/§118)", () => {
  it("§102: search export is CSV, row-limited and audited", async () => {
    const s = makeStack();
    await s.prisma.securitySearchDocument.create({ data: {
      id: "doc-e", organizationId: "org-1", workspaceId: "ws-1", documentType: "ASSET", resourceId: "a-e",
      title: "export-host", summary: "", searchableText: "export-host",
      facets: {}, classification: "INTERNAL", riskScore: 5, severity: null,
    } as never });
    const out = await s.exportsSvc.exportAnalytics(ENGINEER, WS, { kind: "SEARCH", query: "export-host", format: "CSV" });
    expect(String(out.content)).toContain("documentType");
    expect(String(out.content)).toContain("export-host");
    expect(out.rowCount).toBe(1);
    expect(s.audit.record.calls.length).toBeGreaterThan(0);
  });

  it("§142: cache entries are unreachable across tenants/security contexts", () => {
    const s = makeStack();
    const keyA = s.cache.keyFor(OWNER, "ws-1", "OVERVIEW", {});
    s.cache.set(OWNER, "ws-1", keyA, { secret: "tenant-a" });
    expect(s.cache.get(keyA)).toEqual({ secret: "tenant-a" });
    const keyB = s.cache.keyFor(OTHER_ORG, "ws-2", "OVERVIEW", {});
    expect(keyB).not.toBe(keyA);
    expect(s.cache.get(keyB)).toBeNull();
    const keyViewer = s.cache.keyFor(VIEWER, "ws-1", "OVERVIEW", {});
    expect(keyViewer).not.toBe(keyA); // different role/permissions/classification ceiling
  });

  it("§143: retention deletes expired lake records but never audit records", async () => {
    const s = makeStack();
    await s.store.writeEvent({
      eventId: "old-evt", organizationId: "org-1", workspaceId: "ws-1", eventType: "FINDING_CREATED",
      eventTime: "2020-01-01T00:00:00.000Z", sourceType: "FIXTURE", resourceType: "FINDING", resourceId: "f-old",
      classification: "INTERNAL", attributes: {},
    });
    await s.prisma.auditLog.create({ data: {
      id: "audit-1", organizationId: "org-1", workspaceId: "ws-1", action: "LOGIN", resourceType: "User",
    } as never });
    const out = await s.retention.runRetention("ws-1", new Date("2026-10-08T00:00:00Z"));
    expect(out.eventsDeleted).toBe(1);
    expect(await s.prisma.auditLog.count({})).toBe(1); // audit trail untouched (§114/§148)
  });

  it("§144: reindex rebuilds documents with tenant scope intact", async () => {
    const s = makeStack();
    await seedWorkspaces(s);
    await s.prisma.asset.create({ data: {
      id: "a-re", workspaceId: "ws-1", targetId: "t-1", host: "reindex-host", ip: "192.168.1.10",
      type: "HOST", scopeStatus: "IN_SCOPE", sources: [], criticality: "LOW",
    } as never });
    await s.prisma.asset.create({ data: {
      id: "a-other", workspaceId: "ws-2", targetId: "t-2", host: "other-host", ip: "192.168.1.11",
      type: "HOST", scopeStatus: "IN_SCOPE", sources: [], criticality: "LOW",
    } as never });
    const out = await s.retention.runReindex(SCOPE, "u-owner");
    expect(out.status).toBe("COMPLETED");
    expect(out.documentsNow).toBe(1); // only ws-1 documents — ws-2 untouched
    const docs = await s.prisma.securitySearchDocument.findMany({ where: { workspaceId: "ws-1" } });
    expect(docs[0]!.title).toBe("reindex-host");
  });

  it("§118: health reports lag, dead letters and index state", async () => {
    const s = makeStack();
    await s.ingestion.ingestBatch(SCOPE, [eventRow({ eventType: "BOGUS" }), eventRow({ eventId: "health-ok" })]);
    const health = await s.health.health("ws-1");
    expect(health.deadLetterCount).toBe(1);
    expect(health.alerts).toContain("SEARCH_INDEX_EMPTY");
    expect(health.performanceBudgets.searchP95Ms).toBe(750);
  });
});
