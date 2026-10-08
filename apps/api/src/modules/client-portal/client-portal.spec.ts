import { ClientPortalService } from "./client-portal.service";
import { VmReportsService } from "../vulnerability-management/vm-reports.service";
import { VmReportingService } from "../vulnerability-management/vm-reporting.service";

/**
 * Prompt 37 client-portal tests (§100–§109, §137, §143–§145) against an
 * in-memory Prisma fake. Fixture data only.
 */

let seq = 0;
const nid = (p: string) => `${p}-${++seq}`;
const now = new Date("2026-10-08T00:00:00Z");
type Row = Record<string, unknown> & { id: string };
const TABLES = [
  "finding", "findingComment", "findingEvidence", "findingHistory", "workspace", "user", "auditLog",
  "securityReport", "reportSnapshot", "reportVersion", "reportShareLink", "reportExport", "reportTemplate",
  "clientOrganization", "clientEngagement", "clientPortalUser", "clientFindingPublication", "clientNotification",
  "remediationCase", "remediationStatusHistory", "retestRequest",
  "findingObservation", "findingCorrelation", "vmNotificationEvent",
];

function cmpVal(a: unknown, b: unknown): boolean {
  if (a instanceof Date && b instanceof Date) return a.getTime() === b.getTime();
  return a === b;
}
function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (k === "OR") { if (!(v as Record<string, unknown>[]).some((w) => matches(row, w))) return false; continue; }
    if (v && typeof v === "object" && !(v instanceof Date)) {
      const cond = v as Record<string, unknown>;
      if ("in" in cond) { if (!(cond.in as unknown[]).some((x) => cmpVal(row[k], x))) return false; continue; }
      if ("not" in cond) { if (cmpVal(row[k], cond.not) && cond.not !== null) return false; if (cond.not === null && row[k] === null) return false; continue; }
      continue;
    }
    if (v === null) { if (row[k] !== null && row[k] !== undefined) return false; continue; }
    if (!cmpVal(row[k], v)) return false;
  }
  return true;
}
function sortRows(rows: Row[], orderBy: unknown): Row[] {
  const specs = (Array.isArray(orderBy) ? orderBy : [orderBy]).filter(Boolean) as Record<string, string>[];
  return [...rows].sort((a, b) => {
    for (const spec of specs) for (const [k, dir] of Object.entries(spec)) {
      const av = a[k] as never, bv = b[k] as never;
      if (av !== bv) return (av < bv ? -1 : 1) * (dir === "desc" ? -1 : 1);
    }
    return 0;
  });
}
function makeTable(store: Map<string, Row[]>, name: string, all: Map<string, Row[]>) {
  const rows = () => store.get(name)!;
  const attach = (row: Row, include?: Record<string, unknown>) => {
    if (!include) return row;
    const out = { ...row };
    if (include.snapshot) out.snapshot = all.get("reportSnapshot")!.find((s) => s.reportId === row.id) ?? null;
    return out;
  };
  return {
    findMany: async (args: { where?: Record<string, unknown>; orderBy?: unknown; take?: number } = {}) => {
      let out = rows().filter((r) => matches(r, args.where));
      if (args.orderBy) out = sortRows(out, args.orderBy);
      if (args.take !== undefined) out = out.slice(0, args.take);
      return out.map((r) => ({ ...r }));
    },
    findFirst: async (args: { where?: Record<string, unknown>; orderBy?: unknown; include?: Record<string, unknown> } = {}) => {
      let out = rows().filter((r) => matches(r, args.where));
      if (args.orderBy) out = sortRows(out, args.orderBy);
      return out[0] ? attach({ ...out[0] }, args.include) : null;
    },
    findUnique: async (args: { where: Record<string, unknown> }) => rows().find((r) => matches(r, args.where)) ?? null,
    count: async (args: { where?: Record<string, unknown> } = {}) => rows().filter((r) => matches(r, args.where)).length,
    create: async (args: { data: Row }) => {
      // Mirror the Prisma column defaults the services rely on.
      const defaults: Record<string, unknown> = name === "securityReport" ? { version: "v1", status: "DRAFT", approvalStatus: "DRAFT" } : {};
      const data = args.data as Record<string, unknown>;
      const row = { ...defaults, id: nid(name), createdAt: now, updatedAt: now, ...data } as Row;
      rows().push(row);
      return { ...row };
    },
    update: async (args: { where: { id: string }; data: Record<string, unknown> }) => {
      const row = rows().find((r) => r.id === args.where.id);
      if (!row) throw new Error("missing row");
      Object.assign(row, args.data);
      return { ...row };
    },
    deleteMany: async (args: { where?: Record<string, unknown> } = {}) => {
      const before = rows().length;
      store.set(name, rows().filter((r) => !matches(r, args.where)));
      return { count: before - store.get(name)!.length };
    },
    delete: async (args: { where: { id: string } }) => {
      const i = rows().findIndex((r) => r.id === args.where.id);
      if (i >= 0) rows().splice(i, 1);
      return {};
    },
  };
}

const WS = "ws-1";
const owner = { id: "owner-1", organizationId: "org-1", email: "o@x.io", role: "OWNER" } as never;
const admin = { id: "admin-1", organizationId: "org-1", email: "a@x.io", role: "ADMIN" } as never;
const clientUser = { id: "client-user-1", organizationId: "org-1", email: "c@client.io", role: "CLIENT_REMEDIATOR" } as never;
const stranger = { id: "stranger-1", organizationId: "org-9", email: "s@other.io", role: "CLIENT_VIEWER" } as never;

describe("Prompt 37 — client portal", () => {
  let store: Map<string, Row[]>;
  let portal: ClientPortalService;
  let reportsSvc: VmReportsService;
  let reporting: VmReportingService;
  let engagementId: string;
  let findingId: string;
  const auditCalls: { action: string }[] = [];
  const audit = { record: async (x: { action: string }) => { auditCalls.push(x); return {}; } };

  beforeEach(async () => {
    const map = new Map<string, Row[]>(TABLES.map((t) => [t, []]));
    store = map;
    const prisma: Record<string, unknown> = {};
    for (const t of TABLES) prisma[t] = makeTable(map, t, map);
    portal = new ClientPortalService(prisma as never, audit as never);
    reportsSvc = new VmReportsService(prisma as never, audit as never);
    reporting = new VmReportingService(prisma as never, audit as never);

    store.get("workspace")!.push({ id: WS, organizationId: "org-1", name: "W" } as Row);
    store.get("user")!.push({ id: "client-user-1", email: "c@client.io", createdAt: now, updatedAt: now } as Row);
    const client = await portal.createClient(owner, WS, { name: "Rudra Retail", slug: "rudra-retail" });
    const eng = await portal.createEngagement(owner, WS, { clientOrganizationId: client.id, name: "2026 Annual VAPT" });
    engagementId = eng.id;
    await portal.bindPortalUser(owner, WS, { userId: "client-user-1", clientOrganizationId: client.id, portalRole: "CLIENT_REMEDIATOR" });

    const f: Row = {
      id: nid("finding"), workspaceId: WS, scanId: "scan-1", assetId: "asset-1", title: "Reflected XSS",
      description: "reflected via q parameter; internal note: password: hunter2 in test account",
      severity: "HIGH", status: "OPEN", lifecycleStatus: "CONFIRMED", sources: ["NUCLEI"], fingerprint: "fp-1",
      priority: "P1", firstSeen: now, lastSeen: now, createdAt: now, updatedAt: now, recurrenceCount: 0,
      kevListed: false, epssScore: null, riskScore: 72, dueAt: null, verificationStatus: "UNVERIFIED",
      cve: null, cwe: "CWE-79", host: "shop.example.test", endpoint: "https://shop.example.test/search",
      remediation: "Encode output contextually.",
    };
    store.get("finding")!.push(f);
    findingId = f.id;
    store.get("findingEvidence")!.push(
      { id: nid("ev"), findingId, sourceTool: "NUCLEI", evidenceType: "TEXT", summary: "internal raw capture with cookie: session=zzz", visibility: "INTERNAL", createdAt: now, updatedAt: now } as Row,
      { id: nid("ev"), findingId, sourceTool: "NUCLEI", evidenceType: "TEXT", summary: "sanitized request/response pair", visibility: "CLIENT", createdAt: now, updatedAt: now } as Row,
    );
    store.get("findingComment")!.push(
      { id: nid("cm"), findingId, workspaceId: WS, authorId: "analyst-1", text: "internal: reproduced with admin session", visibility: "INTERNAL", mentions: [], createdAt: now, updatedAt: now } as Row,
      { id: nid("cm"), findingId, workspaceId: WS, authorId: "analyst-1", text: "client-facing status note", visibility: "CLIENT", mentions: [], createdAt: now, updatedAt: now } as Row,
    );
  });

  it("nothing is portal-visible before publication (§100)", async () => {
    expect(await portal.myFindings(clientUser, engagementId)).toEqual([]);
    await expect(portal.myFinding(clientUser, engagementId, findingId)).rejects.toMatchObject({ status: 404 });
  });

  it("publication exposes only the client projection — no internal data, no secrets (§101/§142/§143)", async () => {
    await portal.publishFinding(owner, WS, engagementId, findingId);
    const view = await portal.myFinding(clientUser, engagementId, findingId);
    const json = JSON.stringify(view);
    expect(view.title).toBe("Reflected XSS");
    expect(json).not.toContain("hunter2");
    expect(json).not.toContain("session=zzz");
    expect(json).not.toContain("internal raw capture");
    expect(json).not.toContain("reproduced with admin session");
    expect(json).toContain("client-facing status note");
    expect(json).toContain("sanitized request/response pair");
    expect(view.status).toBe("CONFIRMED");
  });

  it("unpublishing revokes access immediately (§100)", async () => {
    await portal.publishFinding(owner, WS, engagementId, findingId);
    await portal.unpublishFinding(owner, WS, engagementId, findingId);
    await expect(portal.myFinding(clientUser, engagementId, findingId)).rejects.toMatchObject({ status: 404 });
  });

  it("client isolation: other organizations' engagements are 404, never 403 (§144)", async () => {
    const other = await portal.createClient(owner, WS, { name: "Other Co", slug: "other-co" });
    const otherEng = await portal.createEngagement(owner, WS, { clientOrganizationId: other.id, name: "Theirs" });
    await expect(portal.myFindings(clientUser, otherEng.id)).rejects.toMatchObject({ status: 404 });
    await expect(portal.myFindings(stranger, engagementId)).rejects.toMatchObject({ status: 404 });
    await expect(portal.dashboard(stranger)).rejects.toMatchObject({ status: 404 });
  });

  it("client comments are forced CLIENT visibility (§102)", async () => {
    await portal.publishFinding(owner, WS, engagementId, findingId);
    const row = await portal.comment(clientUser, engagementId, findingId, "we deployed a fix");
    expect(row.visibility).toBe("CLIENT");
  });

  it("a client fix claim lands on FIX_CLAIMED — never verified closure (§137/§103/§30)", async () => {
    await portal.publishFinding(owner, WS, engagementId, findingId);
    const out = await portal.claimFix(clientUser, engagementId, findingId, "patched in release 42");
    expect(out.status).toBe("FIX_CLAIMED");
    expect(out.verifiedClosure).toBe(false);
    const kase = store.get("remediationCase")!.find((c) => c.findingId === findingId)!;
    expect(kase.status).toBe("FIX_CLAIMED");
    expect(store.get("finding")!.find((f) => f.id === findingId)!.lifecycleStatus).toBe("CONFIRMED"); // unchanged
  });

  it("retest requests queue on the governed path (§104)", async () => {
    await portal.publishFinding(owner, WS, engagementId, findingId);
    const out = await portal.requestRetest(clientUser, engagementId, findingId);
    expect(out.status).toBe("QUEUED");
    expect(store.get("retestRequest")![0]!.status).toBe("QUEUED");
  });

  it("portal reports: only finalized + client-scoped; downloads render the frozen version (§105)", async () => {
    const report = await reportsSvc.createReport(owner, WS, { title: "Client report", type: "EXECUTIVE" });
    store.get("securityReport")!.find((r) => r.id === report.id)!.clientOrganizationId =
      store.get("clientOrganization")![0]!.id;
    await reportsSvc.generate(owner, WS, report.id);
    expect(await portal.myReports(clientUser, engagementId)).toEqual([]); // not finalized yet
    await reporting.submitReview(owner, WS, report.id);
    await reporting.approve(admin, WS, report.id);
    await reporting.finalize(owner, WS, report.id);
    const list = await portal.myReports(clientUser, engagementId);
    expect(list.length).toBe(1);
    const dl = await portal.downloadReport(clientUser, engagementId, report.id, "JSON");
    expect(dl.checksum).toMatch(/^[0-9a-f]{64}$/);
    expect(String(dl.content)).not.toContain("hunter2");
  });

  it("secure share links: token works once governed, revocation/expiry/limits deny (§145/§106)", async () => {
    const report = await reportsSvc.createReport(owner, WS, { title: "Shared", type: "EXECUTIVE" });
    await reportsSvc.generate(owner, WS, report.id);
    await reporting.submitReview(owner, WS, report.id);
    await reporting.approve(admin, WS, report.id);
    await reporting.finalize(owner, WS, report.id);

    const link = await reporting.createShareLink(owner, WS, report.id, { expiresInHours: 1, maxDownloads: 1 });
    const got = await portal.resolveSharedReport(link.token, "HTML");
    expect(got.sizeBytes).toBeGreaterThan(0);
    // download limit reached
    await expect(portal.resolveSharedReport(link.token, "HTML")).rejects.toMatchObject({ status: 404 });

    const link2 = await reporting.createShareLink(owner, WS, report.id, { expiresInHours: 1 });
    await reporting.revokeShareLink(owner, WS, report.id, link2.id);
    await expect(portal.resolveSharedReport(link2.token, "HTML")).rejects.toMatchObject({ status: 404 });

    const link3 = await reporting.createShareLink(owner, WS, report.id, { expiresInHours: -1 }); // already expired
    await expect(portal.resolveSharedReport(link3.token, "HTML")).rejects.toMatchObject({ status: 404 });
    await expect(portal.resolveSharedReport("not-a-real-token", "HTML")).rejects.toMatchObject({ status: 404 });
    // hashes never leave the API
    const listed = await reporting.listShareLinks(owner, WS, report.id);
    expect(JSON.stringify(listed)).not.toContain("tokenHash");
  });

  it("portal access is audited and publication notifies the client (§129/§108)", async () => {
    auditCalls.length = 0;
    await portal.publishFinding(owner, WS, engagementId, findingId);
    await portal.myFinding(clientUser, engagementId, findingId);
    const actions = auditCalls.map((c) => c.action);
    expect(actions).toContain("CLIENT_FINDING_PUBLISHED");
    expect(actions).toContain("CLIENT_PORTAL_ACCESSED");
    expect(store.get("clientNotification")!.length).toBeGreaterThan(0);
    const note = store.get("clientNotification")![0]!;
    expect(String(note.body)).not.toContain("hunter2"); // §109: notifications carry client-visible text only
  });
});
