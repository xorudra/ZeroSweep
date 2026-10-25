import { BadRequestException, ForbiddenException } from "@nestjs/common";
import { FIXTURE_CVE, NESSUS_FIXTURE, NESSUS_XXE_ATTACK } from "@zerosweep/security-sdk";
import { VulnerabilityService } from "./vulnerability.service";
import { IntelligenceService } from "./intelligence.service";
import { RetestService } from "./retest.service";
import { ScannerImportsService } from "./imports.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Prompt 11 API tests (§93–§101): lifecycle rules, permission gates,
 * tenant isolation, enrichment honesty (empty dataset attaches NOTHING),
 * dashboard metrics from real rows, hostile import handling. All data is
 * in-memory fixtures; intelligence tables start EMPTY.
 */

const WS = "ws-1";
const OTHER_WS = "ws-2";
const admin: RequestUser = { id: "u-admin", email: "rudra@example.com", organizationId: "org-1", role: "ADMIN" };
const analyst: RequestUser = { id: "u-analyst", email: "a@example.com", organizationId: "org-1", role: "ANALYST" };
const viewer: RequestUser = { id: "u-viewer", email: "v@example.com", organizationId: "org-1", role: "VIEWER" };

type Row = Record<string, unknown> & { id: string };

function matches(row: Row, where: Record<string, unknown> = {}, tables: Record<string, Row[]>): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (v === undefined) continue;
    if (k === "finding" && typeof v === "object") {
      const f = tables.finding!.find((x) => x.id === row.findingId);
      if (!f || !matches(f, v as Record<string, unknown>, tables)) return false;
      continue;
    }
    const rv = row[k];
    if (v !== null && typeof v === "object" && !(v instanceof Date)) {
      const cond = v as Record<string, unknown>;
      if ("in" in cond && !(cond.in as unknown[]).includes(rv)) return false;
      if ("gte" in cond && !((rv as Date) >= (cond.gte as Date))) return false;
      if ("lte" in cond && !((rv as Date) <= (cond.lte as Date))) return false;
      if ("has" in cond && !(Array.isArray(rv) && rv.includes(cond.has))) return false;
      if ("contains" in cond && !(typeof rv === "string" && rv.toLowerCase().includes(String(cond.contains).toLowerCase()))) return false;
      continue;
    }
    if (rv !== v) return false;
  }
  return true;
}

const MODEL_DEFAULTS: Record<string, Partial<Row>> = {
  retestRequest: { status: "QUEUED" },
  scannerReportImport: { status: "PREVIEW" },
};

function makeModel(name: string, tables: Record<string, Row[]>) {
  const rows = () => tables[name]!;
  let seq = 0;
  return {
    async findMany(args: { where?: Record<string, unknown>; orderBy?: unknown; take?: number } = {}) {
      let out = rows().filter((r) => matches(r, args.where, tables));
      if (args.take) out = out.slice(0, args.take);
      return out;
    },
    async findFirst(args: { where?: Record<string, unknown> } = {}) {
      return rows().find((r) => matches(r, args.where, tables)) ?? null;
    },
    async findUnique(args: { where: Record<string, unknown> }) {
      return rows().find((r) => matches(r, args.where, tables)) ?? null;
    },
    async create(args: { data: Row & { history?: { create: Row }; references?: { create: Row[] } } }) {
      const { history, references, ...data } = args.data;
      const row: Row = { ...(MODEL_DEFAULTS[name] ?? {}), ...data, id: `${name}-${++seq}-${rows().length}`, createdAt: new Date(), updatedAt: new Date() };
      rows().push(row);
      if (history?.create) tables.findingHistory!.push({ ...history.create, id: `h-${rows().length}`, findingId: row.id });
      if (references?.create) for (const ref of references.create) tables.findingReference!.push({ ...ref, id: `r-${row.id}`, findingId: row.id });
      return row;
    },
    async update(args: { where: Record<string, unknown>; data: Row }) {
      const row = rows().find((r) => matches(r, args.where, tables));
      if (!row) throw new Error("record not found");
      Object.assign(row, args.data);
      return row;
    },
    async upsert(args: { where: Record<string, unknown>; create: Row; update: Row }) {
      // resolve compound unique wheres of the shape { a_b: { a, b } }
      const flat: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(args.where)) {
        if (v !== null && typeof v === "object" && !(v instanceof Date)) Object.assign(flat, v);
        else flat[k] = v;
      }
      const existing = rows().find((r) => matches(r, flat, tables));
      if (existing) { Object.assign(existing, args.update); return existing; }
      const row: Row = { ...args.create, id: `${name}-${++seq}-${rows().length}`, createdAt: new Date(), updatedAt: new Date() };
      rows().push(row);
      return row;
    },
    async count(args: { where?: Record<string, unknown> } = {}) {
      return rows().filter((r) => matches(r, args.where, tables)).length;
    },
    async groupBy(args: { by: string[]; where?: Record<string, unknown> }) {
      const groups = new Map<string, Row & { _count: { _all: number } }>();
      for (const r of rows().filter((x) => matches(x, args.where, tables))) {
        const key = args.by.map((b) => String(r[b])).join("|");
        const g = groups.get(key) ?? { ...Object.fromEntries(args.by.map((b) => [b, r[b]])), _count: { _all: 0 } } as Row & { _count: { _all: number } };
        g._count._all++;
        groups.set(key, g);
      }
      return [...groups.values()];
    },
    async delete(args: { where: Record<string, unknown> }) {
      const idx = rows().findIndex((r) => matches(r, args.where, tables));
      if (idx >= 0) rows().splice(idx, 1);
      return {};
    },
  };
}

function harness() {
  const tables: Record<string, Row[]> = {
    workspace: [{ id: WS, organizationId: "org-1" }, { id: OTHER_WS, organizationId: "org-1" }],
    finding: [], findingHistory: [], findingComment: [], findingObservation: [], findingEvidence: [],
    findingReference: [], exploitReference: [], retestRequest: [], remediationSlaPolicy: [],
    cveRecord: [], cweRecord: [], cpeRecord: [], epssRecord: [], kevRecord: [], intelligenceSyncState: [],
    asset: [], scan: [], scannerReportImport: [], auditLog: [], toolExecution: [],
  };
  const prisma = Object.fromEntries(Object.keys(tables).map((k) => [k, makeModel(k, tables)])) as never;
  const audit = new AuditService(prisma);
  const intelligence = new IntelligenceService(prisma, null);
  const vulnerabilities = new VulnerabilityService(prisma, audit, intelligence);
  const retests = new RetestService(prisma, audit, vulnerabilities, { enqueueRetest: async () => true } as never);
  const imports = new ScannerImportsService(prisma, audit);
  return { tables, prisma, intelligence, vulnerabilities, retests, imports };
}

let findingSeq = 0;
function seedFinding(tables: Record<string, Row[]>, over: Partial<Row> = {}): Row {
  const row: Row = {
    id: `f-${++findingSeq}`, workspaceId: WS, scanId: "scan-1", assetId: "asset-1",
    fingerprint: "fp-1", title: "Apache Log4j RCE", description: "fixture", severity: "CRITICAL",
    status: "OPEN", verificationStatus: "UNVERIFIED", confidence: 0.8, confidenceBand: "HIGH",
    host: "192.0.2.10", port: 8080, endpoint: null, parameter: null, cve: FIXTURE_CVE, cwe: "CWE-502",
    vulnClass: "GENERIC_VULNERABILITY", cpe: null, cvssScore: 10, cvssVector: null, owaspCategory: null,
    remediation: "Upgrade", sources: ["nuclei"], isMock: false, riskScore: 90, riskBand: "CRITICAL",
    riskExplanation: [], lifecycleStatus: "NEW", detectionKind: "DETECTED_VULNERABILITY",
    priority: null, riskFactors: null, riskCalcVersion: null, intelSnapshot: null, intelCvssScore: null,
    epssScore: null, epssPercentile: null, kevListed: false, exploitRefExists: false,
    assignedToId: null, assignedToTeam: null, assignedBy: null, assignedAt: null, tags: [],
    slaPolicyId: null, dueAt: null, resolvedAt: null, reopenedAt: null, recurrenceCount: 0,
    riskAcceptanceReason: null, riskAcceptedBy: null, riskAcceptanceExpiresAt: null,
    duplicateOfId: null, technicalImpact: null, businessImpact: null, protocol: null,
    reviewStatus: null, reviewedBy: null, reviewedAt: null, reviewNotes: null,
    firstSeen: new Date("2026-09-01T00:00:00Z"), lastSeen: new Date("2026-10-01T00:00:00Z"),
    createdAt: new Date("2026-09-01T00:00:00Z"), updatedAt: new Date("2026-10-01T00:00:00Z"),
    ...over,
  };
  tables.finding!.push(row);
  return row;
}

describe("lifecycle + permissions (§47–§51, §78)", () => {
  it("drives the full lifecycle and audits each step", async () => {
    const h = harness();
    const f = seedFinding(h.tables);
    await h.vulnerabilities.transition(analyst, WS, f.id, { to: "TRIAGED" });
    await h.vulnerabilities.transition(analyst, WS, f.id, { to: "CONFIRMED" });
    const row = h.tables.finding!.find((r) => r.id === f.id)!;
    expect(row.lifecycleStatus).toBe("CONFIRMED");
    expect(row.status).toBe("CONFIRMED");
    expect(row.dueAt).toBeInstanceOf(Date); // SLA anchor at confirmation (§42)
    expect(h.tables.auditLog!.length).toBeGreaterThanOrEqual(2);
  });

  it("rejects FALSE_POSITIVE → IN_PROGRESS without reopen (§48)", async () => {
    const h = harness();
    const f = seedFinding(h.tables, { lifecycleStatus: "FALSE_POSITIVE", status: "FALSE_POSITIVE" });
    await expect(h.vulnerabilities.transition(admin, WS, f.id, { to: "IN_PROGRESS" })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("risk acceptance needs the ACCEPT_RISK permission + reason + approver + expiry (§49/§78)", async () => {
    const h = harness();
    const f = seedFinding(h.tables, { lifecycleStatus: "TRIAGED" });
    await expect(h.vulnerabilities.transition(analyst, WS, f.id, {
      to: "ACCEPTED_RISK", reason: "control", riskAcceptance: { approverId: admin.id, expiresAt: new Date(Date.now() + 86400_000) },
    })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(h.vulnerabilities.transition(admin, WS, f.id, { to: "ACCEPTED_RISK" })).rejects.toBeInstanceOf(BadRequestException);
    const ok = await h.vulnerabilities.transition(admin, WS, f.id, {
      to: "ACCEPTED_RISK", reason: "compensating control in place", riskAcceptance: { approverId: admin.id, expiresAt: new Date(Date.now() + 86400_000) },
    });
    expect(ok.lifecycleStatus).toBe("ACCEPTED_RISK");
  });

  it("false positive needs a reason and keeps the record + evidence (§51)", async () => {
    const h = harness();
    const f = seedFinding(h.tables, { lifecycleStatus: "TRIAGED" });
    await expect(h.vulnerabilities.transition(admin, WS, f.id, { to: "FALSE_POSITIVE", reviewerId: admin.id })).rejects.toBeInstanceOf(BadRequestException);
    const ok = await h.vulnerabilities.transition(admin, WS, f.id, { to: "FALSE_POSITIVE", reason: "banner-only match", reviewerId: admin.id });
    expect(ok.lifecycleStatus).toBe("FALSE_POSITIVE");
    expect(h.tables.finding!.find((r) => r.id === f.id)).toBeTruthy(); // never deleted
  });

  it("assignment + comments are permission-checked, sanitized and audited (§44/§45)", async () => {
    const h = harness();
    const f = seedFinding(h.tables);
    await expect(h.vulnerabilities.assign(viewer, WS, f.id, { assignedToId: analyst.id })).rejects.toBeInstanceOf(ForbiddenException);
    await h.vulnerabilities.assign(admin, WS, f.id, { assignedToId: analyst.id });
    const comment = await h.vulnerabilities.addComment(analyst, WS, f.id, "Looking <script>alert(1)</script> into it");
    expect((comment as Row).text).toBe("Looking alert(1) into it");
    expect(h.tables.auditLog!.some((a) => a.action === "VULNERABILITY_ASSIGNED")).toBe(true);
  });

  it("tenant isolation: another workspace's finding is invisible (§100)", async () => {
    const h = harness();
    const f = seedFinding(h.tables, { workspaceId: OTHER_WS });
    await expect(h.vulnerabilities.getFinding(WS, f.id)).rejects.toThrow(/not found/);
    const list = await h.vulnerabilities.list(WS, {});
    expect(list.total).toBe(0);
  });
});

describe("enrichment honesty (§35/§87)", () => {
  it("empty intelligence dataset attaches NOTHING — epss stays null, kev false", async () => {
    const h = harness();
    const f = seedFinding(h.tables);
    const { view, enrichment } = await h.vulnerabilities.applyEnrichment(admin, WS, f.id);
    expect(enrichment.epss).toBeUndefined();
    expect(enrichment.kevListed).toBe(false);
    expect(view.epssScore).toBeNull();
    expect(view.kevListed).toBe(false);
    const states = await h.intelligence.syncStates();
    expect(states.every((s) => s.status === "NEVER_SYNCED")).toBe(true);
  });

  it("a sync attempt with no fetcher configured fails honestly (§30)", async () => {
    const h = harness();
    const outcome = await h.intelligence.runSync("NVD");
    expect(outcome.status).toBe("FAILED");
    const states = await h.intelligence.syncStates();
    expect(states.find((s) => s.source === "NVD")?.status).toBe("FAILED");
  });

  it("seeded local records enrich for real: EPSS + KEV flow into risk + priority", async () => {
    const h = harness();
    h.tables.cveRecord!.push({ id: "cve-1", cveId: FIXTURE_CVE, description: "Log4Shell", cvssScore: 10, cvssVector: "CVSS:3.1/AV:N", cvssVersion: "3.1", cweIds: ["CWE-502"], references: [], source: "NVD", publishedAt: null, modifiedAt: null, createdAt: new Date(), updatedAt: new Date() });
    h.tables.epssRecord!.push({ id: "e-1", cveId: FIXTURE_CVE, score: 0.94358, percentile: 0.99913, date: new Date("2026-10-01"), source: "FIRST_EPSS", createdAt: new Date() });
    h.tables.kevRecord!.push({ id: "k-1", cveId: FIXTURE_CVE, dateAdded: new Date("2021-12-10"), vendorProject: "Apache", product: "Log4j2", vulnerabilityName: "Log4Shell", requiredAction: "Patch", dueDate: null, knownRansomwareUse: "Known", source: "CISA_KEV", createdAt: new Date(), updatedAt: new Date() });
    const f = seedFinding(h.tables);
    const { view, enrichment } = await h.vulnerabilities.applyEnrichment(admin, WS, f.id);
    expect(enrichment.epss?.score).toBeCloseTo(0.94358);
    expect(view.epssScore).toBeCloseTo(0.94358);
    expect(view.kevListed).toBe(true);
    expect(view.priority).toBe("P0");
    expect(h.tables.finding!.find((r) => r.id === f.id)!.intelSnapshot).toBeTruthy();
  });

  it("CVE detail reports affected findings only for the caller's workspace (§69/§100)", async () => {
    const h = harness();
    seedFinding(h.tables);
    seedFinding(h.tables, { workspaceId: OTHER_WS, fingerprint: "fp-2" });
    const detail = await h.intelligence.cveDetail(FIXTURE_CVE, WS);
    expect(detail.hasIntelligenceData).toBe(false); // no local record — honest
    expect(detail.affectedFindings).toHaveLength(1);
  });
});

describe("dashboard metrics (§65/§90/§91)", () => {
  it("computes from real rows only; MTTR is null with nothing resolved", async () => {
    const h = harness();
    seedFinding(h.tables);
    seedFinding(h.tables, { fingerprint: "fp-2", lifecycleStatus: "RESOLVED", status: "RESOLVED", resolvedAt: new Date("2026-09-03T00:00:00Z"), priority: "P1" });
    const dash = await h.vulnerabilities.dashboard(WS);
    expect(dash.totalOpen).toBe(1);
    expect(dash.meanTimeToRemediateHours).toBeCloseTo(48);
    expect(dash.definitions.openVulnerability).toBeTruthy();
    const empty = await h.vulnerabilities.dashboard(OTHER_WS);
    expect(empty.totalOpen).toBe(0);
    expect(empty.meanTimeToRemediateHours).toBeNull();
  });
});

describe("retest requests (§55–§58)", () => {
  it("creates a targeted plan from the original tool and moves REMEDIATED → RETEST_PENDING", async () => {
    const h = harness();
    const f = seedFinding(h.tables, { lifecycleStatus: "REMEDIATED" });
    const retest = await h.retests.requestRetest(admin, WS, f.id, "patch deployed");
    expect((retest as Row).sourceTool).toBe("nuclei");
    expect((retest as Row).status).toBe("QUEUED");
    expect(h.tables.finding!.find((r) => r.id === f.id)!.lifecycleStatus).toBe("RETEST_PENDING");
    expect(h.tables.auditLog!.some((a) => a.action === "RETEST_REQUESTED")).toBe(true);
  });

  it("refuses a retest for a finding that was never remediated", async () => {
    const h = harness();
    const f = seedFinding(h.tables, { lifecycleStatus: "NEW" });
    await expect(h.retests.requestRetest(admin, WS, f.id)).rejects.toBeInstanceOf(BadRequestException);
  });
});

describe("scanner report imports (§74–§76, §101)", () => {
  it("previews with scope verdicts; out-of-scope hosts quarantine instead of importing", async () => {
    const h = harness();
    h.tables.asset!.push({ id: "asset-1", workspaceId: WS, host: "192.0.2.10", scopeStatus: "IN_SCOPE", criticality: "HIGH" });
    h.tables.scan!.push({ id: "scan-1", workspaceId: WS });
    const preview = await h.imports.preview(admin, WS, { scanner: "nessus-professional", raw: NESSUS_FIXTURE });
    expect(preview.totalFindings).toBe(2);
    expect(preview.importableFindings).toBe(2);
    expect(preview.decision).toBe("IMPORT");
    const committed = await h.imports.commit(admin, WS, preview.importId, NESSUS_FIXTURE, "scan-1");
    expect(committed.imported).toBe(2);
    expect(h.tables.findingObservation!.length).toBe(2);
    // Second commit of the same report → duplicates become observations (§63).
    const preview2 = await h.imports.preview(admin, WS, { scanner: "nessus-professional", raw: NESSUS_FIXTURE });
    const again = await h.imports.commit(admin, WS, preview2.importId, NESSUS_FIXTURE, "scan-1");
    expect(again.imported).toBe(0);
    expect(again.duplicates).toBe(2);
  });

  it("rejects XXE reports and records the rejection (§76/§101)", async () => {
    const h = harness();
    await expect(h.imports.preview(admin, WS, { scanner: "nessus-professional", raw: NESSUS_XXE_ATTACK })).rejects.toBeInstanceOf(BadRequestException);
    expect(h.tables.scannerReportImport!.some((r) => r.status === "REJECTED")).toBe(true);
  });

  it("commit refuses a payload whose checksum differs from the preview (§75)", async () => {
    const h = harness();
    h.tables.asset!.push({ id: "asset-1", workspaceId: WS, host: "192.0.2.10", scopeStatus: "IN_SCOPE", criticality: "HIGH" });
    h.tables.scan!.push({ id: "scan-1", workspaceId: WS });
    const preview = await h.imports.preview(admin, WS, { scanner: "nessus-professional", raw: NESSUS_FIXTURE });
    await expect(h.imports.commit(admin, WS, preview.importId, NESSUS_FIXTURE.replace("155275", "999999"), "scan-1")).rejects.toThrow(/checksum/);
  });
});

describe("CSV export (§83)", () => {
  it("neutralizes formula-injection cells", async () => {
    const h = harness();
    seedFinding(h.tables, { title: "=cmd|'/C calc'!A0" });
    const csv = await h.vulnerabilities.exportCsv(WS);
    expect(csv).toContain("\"'=cmd|");
    expect(csv).not.toContain("\n\"=cmd");
  });
});
