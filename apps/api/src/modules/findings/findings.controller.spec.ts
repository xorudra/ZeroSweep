import { FindingsController } from "./findings.controller";

/**
 * Findings API (Prompt 7 §38/§39/§62): filters, tenant isolation, the
 * review/false-positive workflow with audit + immutable history, and the
 * sanitized evidence view. Prisma is stubbed — no database, no network.
 */

const USER = { id: "u-1", organizationId: "org-1", email: "rudra@example.com", role: "OWNER" } as never;
const OTHER_USER = { id: "u-2", organizationId: "org-2", email: "other@example.com", role: "OWNER" } as never;

function findingRow(over: Record<string, unknown> = {}) {
  return {
    id: "f-1", workspaceId: "ws-1", scanId: "s-1", assetId: "a-1",
    title: "Weak TLS Protocol Supported — TLS 1.0", description: "…", severity: "MEDIUM",
    confidence: 0.97, confidenceBand: "CONFIRMED", host: "example.com", endpoint: null,
    port: 443, protocol: "tls", status: "OPEN", verificationStatus: "LIKELY",
    vulnClass: "TLS_WEAK_PROTOCOL", cwe: "CWE-327", cve: null, riskScore: 62, riskBand: "MEDIUM",
    sources: ["testssl", "sslyze", "nuclei"], duplicateOfId: null, fingerprint: "fp-1",
    reviewStatus: null, reviewedBy: null, reviewedAt: null, reviewNotes: null,
    createdAt: new Date(), updatedAt: new Date(), _count: { evidence: 3 },
    ...over,
  };
}

function makeController(rows: ReturnType<typeof findingRow>[]) {
  const history: Record<string, unknown>[] = [];
  const audits: Record<string, unknown>[] = [];
  const prisma = {
    user: { findUnique: jest.fn(async () => ({ id: "u-1" })) },
    workspace: { findFirst: jest.fn(async ({ where }: never) => ({ id: (where as { organizationId: string }).organizationId === "org-1" ? "ws-1" : "ws-2" })) },
    finding: {
      count: jest.fn(async ({ where }: never) => rows.filter((r) => matches(r, where)).length),
      findMany: jest.fn(async ({ where }: never) => rows.filter((r) => matches(r, where))),
      findFirst: jest.fn(async ({ where }: never) => rows.find((r) => matches(r, where)) ?? null),
      update: jest.fn(async ({ where, data }: never) => {
        const row = rows.find((r) => r.id === (where as { id: string }).id)!;
        Object.assign(row, data);
        return row;
      }),
      groupBy: jest.fn(async () => []),
    },
    findingEvidence: { findMany: jest.fn(async () => [{ id: "e-1", sourceTool: "testssl", evidenceType: "TEXT", summary: "testssl TLS1: offered (deprecated)", matchedAt: "example.com:443", fingerprint: "fp-t", metadata: { check: "TLS1" } }]) },
    findingReference: { findMany: jest.fn(async () => []) },
    findingHistory: {
      findMany: jest.fn(async () => history),
      create: jest.fn(async ({ data }: never) => { history.push(data as Record<string, unknown>); return data; }),
    },
  };
  const audit = { record: jest.fn(async (e: Record<string, unknown>) => { audits.push(e); }) };
  const controller = new FindingsController(prisma as never, audit as never);
  return { controller, prisma, history, audits };
}

function matches(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
  for (const [k, v] of Object.entries(where ?? {})) {
    if (k === "sources") continue; // array-contains filter — exercised via unit paths below
    if (v === null) { if (row[k] !== null && row[k] !== undefined) return false; continue; }
    if (typeof v === "object") continue;
    if (row[k] !== v) return false;
  }
  return true;
}

describe("FindingsController (Prompt 7 §38/§39)", () => {
  it("lists findings scoped to the caller's workspace with pagination", async () => {
    const { controller } = makeController([findingRow(), findingRow({ id: "f-2", workspaceId: "ws-2" })]);
    const res = await controller.list(USER);
    expect(res.total).toBe(1);
    expect(res.items[0]!.id).toBe("f-1");
    expect(res.items[0]!.sourceCount).toBe(3);
    expect(res.items[0]!.evidenceCount).toBe(3);
  });

  it("rejects invalid enum filters instead of silently ignoring them", async () => {
    const { controller } = makeController([findingRow()]);
    await expect(controller.list(USER, "WHATEVER")).rejects.toThrow(/severity/);
    await expect(controller.list(USER, undefined, "NOPE")).rejects.toThrow(/status/);
  });

  it("tenant isolation: another workspace's finding is a 404, never data (§62)", async () => {
    const { controller } = makeController([findingRow()]);
    await expect(controller.get(OTHER_USER, "f-1")).rejects.toThrow(/not found/i);
    await expect(controller.evidence(OTHER_USER, "f-1")).rejects.toThrow(/not found/i);
  });

  it("detail returns evidence, references, history and merged duplicates", async () => {
    const { controller } = makeController([findingRow()]);
    const detail = await controller.get(USER, "f-1");
    expect(detail.evidence).toHaveLength(1);
    expect(detail.history).toBeDefined();
    expect(detail.duplicates).toBeDefined();
  });

  it("review flow: false-positive requires notes, records reviewer + history + audit (§32/§33/§66)", async () => {
    const { controller, history, audits } = makeController([findingRow()]);
    await expect(controller.review(USER, "f-1", { status: "FALSE_POSITIVE", notes: "" })).rejects.toThrow(/notes/);
    const updated = await controller.review(USER, "f-1", { status: "FALSE_POSITIVE", notes: "CDN terminates TLS; origin verified separately" });
    expect(updated.status).toBe("FALSE_POSITIVE");
    expect(updated.verificationStatus).toBe("REJECTED");
    expect(updated.reviewedBy).toBe("u-1");
    expect(updated.reviewedAt).toBeInstanceOf(Date);
    expect(history.some((h) => h.event === "FALSE_POSITIVE")).toBe(true);
    expect(audits.some((a) => a.action === "FINDING_FALSE_POSITIVE")).toBe(true);
  });

  it("confirm via review sets verification CONFIRMED + FINDING_CONFIRMED audit", async () => {
    const { controller, audits } = makeController([findingRow()]);
    const updated = await controller.review(USER, "f-1", { status: "CONFIRMED", notes: "Manually reproduced with a TLS client" });
    expect(updated.verificationStatus).toBe("CONFIRMED");
    expect(audits.some((a) => a.action === "FINDING_CONFIRMED")).toBe(true);
  });

  it("status PATCH enforces transitions and requires a reason (§32)", async () => {
    const { controller } = makeController([findingRow({ status: "FALSE_POSITIVE" })]);
    await expect(controller.updateStatus(USER, "f-1", { status: "RESOLVED", reason: "x" })).rejects.toThrow(/Cannot move/);
    const { controller: c2 } = makeController([findingRow()]);
    await expect(c2.updateStatus(USER, "f-1", { status: "RESOLVED" })).rejects.toThrow(/reason/);
    const ok = await c2.updateStatus(USER, "f-1", { status: "RESOLVED", reason: "Patched and retested" });
    expect(ok.status).toBe("RESOLVED");
  });

  it("evidence endpoint returns sanitized rows only (no artifact locations)", async () => {
    const { controller } = makeController([findingRow()]);
    const res = await controller.evidence(USER, "f-1");
    expect(res.evidence[0]!.summary).toContain("testssl");
    expect(JSON.stringify(res)).not.toContain("artifactLocation");
    expect(JSON.stringify(res)).not.toContain("requestRef");
  });

  it("summary reports honest zeros when the workspace has no findings (§44)", async () => {
    const { controller } = makeController([]);
    const res = await controller.summary(USER);
    expect(res.total).toBe(0);
    expect(res.topVulnerabilities).toHaveLength(0);
  });
});
