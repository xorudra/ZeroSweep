import { ForbiddenException, NotFoundException } from "@nestjs/common";
import { resolveWorkspace, assertTargetInOrg } from "../../common/tenant";
import { FindingsController } from "../findings/findings.controller";
import { ReportsController } from "../reports/reports.controller";

/**
 * TenantIsolationTestSuite (Prompt 39 §39–§41).
 *
 * The platform's tenant boundary rests on one choke point — every
 * workspace-bound handler resolves its workspace through
 * `resolveWorkspace(prisma, user[, workspaceId])`, which filters by the
 * caller's organization, and on object queries that always include the
 * resolved `workspaceId`. This suite proves, with two fully populated
 * tenants, that:
 *   1. workspace resolution can never cross organizations (explicit or
 *      default resolution, soft-deleted workspaces included);
 *   2. target ownership assertion is organization-bound;
 *   3. object-level reads/lists/mutations in representative controllers
 *      (findings, reports) return 404/empty for the other tenant — never
 *      foreign data, never a distinguishable existence oracle beyond the
 *      platform's documented 404 policy;
 *   4. mass assignment cannot move a record across tenants: create
 *      payloads naming a foreign workspaceId/scanId are rejected by
 *      scoped lookups (the server never trusts client tenant fields).
 *
 * Prisma is stubbed with a where-aware in-memory store — no database,
 * no network. The live HTTP matrix (two real organizations against the
 * running stack) lives in tests/e2e/ and is executed for RC1 evidence.
 */

const USER_A = { id: "u-a", organizationId: "org-a", email: "rudra@example.com", role: "OWNER" } as never;
const USER_B = { id: "u-b", organizationId: "org-b", email: "other@example.com", role: "OWNER" } as never;

type Row = Record<string, unknown>;

/** Minimal where-matcher supporting the scalar equality + null filters
 *  the controllers under test use. */
function matches(row: Row, where: Row): boolean {
  for (const [k, v] of Object.entries(where ?? {})) {
    if (v === undefined) continue;
    if (v === null) { if (row[k] !== null && row[k] !== undefined) return false; continue; }
    if (typeof v === "object") {
      // relation filter of the shape { organizationId } / { workspace: {...} }
      const rel = v as Row;
      if ("organizationId" in rel) { if (row.__orgId !== rel.organizationId) return false; continue; }
      continue;
    }
    if (row[k] !== v) return false;
  }
  return true;
}

function makeStore() {
  const workspaces: Row[] = [
    { id: "ws-a", organizationId: "org-a", deletedAt: null, createdAt: new Date(1) },
    { id: "ws-b", organizationId: "org-b", deletedAt: null, createdAt: new Date(1) },
    { id: "ws-a-dead", organizationId: "org-a", deletedAt: new Date(), createdAt: new Date(0) },
  ];
  const targets: Row[] = [
    { id: "t-a", deletedAt: null, workspaceId: "ws-a", __orgId: "org-a", workspace: { organizationId: "org-a" } },
    { id: "t-b", deletedAt: null, workspaceId: "ws-b", __orgId: "org-b", workspace: { organizationId: "org-b" } },
  ];
  // The stub expresses the Target->workspace relation filter directly:
  // rows carry __orgId so matches() can evaluate { workspace: { organizationId } }.
  const findings: Row[] = [
    { id: "f-a", workspaceId: "ws-a", status: "OPEN", severity: "HIGH", title: "A finding", sources: [], _count: { evidence: 0 } },
    { id: "f-b", workspaceId: "ws-b", status: "OPEN", severity: "HIGH", title: "B finding", sources: [], _count: { evidence: 0 } },
  ];
  const reports: Row[] = [
    { id: "r-a", workspaceId: "ws-a", scanId: "s-a", format: "PDF", status: "READY" },
    { id: "r-b", workspaceId: "ws-b", scanId: "s-b", format: "PDF", status: "READY" },
  ];
  const scans: Row[] = [
    { id: "123e4567-e89b-12d3-a456-426614174000", workspaceId: "ws-a" },
    { id: "123e4567-e89b-12d3-a456-426614174001", workspaceId: "ws-b" },
  ];
  const table = (rows: Row[]) => ({
    findFirst: jest.fn(async ({ where }: never) => rows.find((r) => matches(r, where as Row)) ?? null),
    findMany: jest.fn(async ({ where }: never) => rows.filter((r) => matches(r, where as Row))),
    count: jest.fn(async ({ where }: never) => rows.filter((r) => matches(r, where as Row)).length),
    create: jest.fn(async ({ data }: never) => ({ id: "new-1", ...(data as Row) })),
    update: jest.fn(async ({ where, data }: never) => {
      const row = rows.find((r) => r.id === (where as Row).id);
      if (row) Object.assign(row, data);
      return row ?? null;
    }),
    groupBy: jest.fn(async () => []),
  });
  const prisma = {
    workspace: {
      findFirst: jest.fn(async ({ where, orderBy }: never) => {
        const w = where as Row;
        const cands = workspaces
          .filter((r) => (w.id === undefined || r.id === w.id)
            && r.organizationId === w.organizationId
            && (w.deletedAt === null ? r.deletedAt === null : true))
          .sort((x, y) => Number((x.createdAt as Date).getTime()) - Number((y.createdAt as Date).getTime()));
        void orderBy;
        return cands[0] ?? null;
      }),
    },
    target: table(targets.map((t) => ({ ...t }))),
    finding: table(findings),
    findingEvidence: { findMany: jest.fn(async () => []) },
    findingReference: { findMany: jest.fn(async () => []) },
    secretFindingMetadata: { findUnique: jest.fn(async () => null) },
    findingHistory: { findMany: jest.fn(async () => []), create: jest.fn(async ({ data }: never) => data) },
    report: table(reports),
    scan: table(scans),
    user: { findUnique: jest.fn(async () => ({ id: "u-a" })) },
  };
  return { prisma, findings, reports };
}

const auditStub = { record: jest.fn(async () => undefined) };

describe("TenantIsolationTestSuite — workspace resolution choke point (§39)", () => {
  it("explicit foreign workspaceId is refused, never resolved", async () => {
    const { prisma } = makeStore();
    await expect(resolveWorkspace(prisma as never, USER_A as never, "ws-b")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(resolveWorkspace(prisma as never, USER_B as never, "ws-a")).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("default resolution stays inside the caller's organization", async () => {
    const { prisma } = makeStore();
    const a = await resolveWorkspace(prisma as never, USER_A as never);
    const b = await resolveWorkspace(prisma as never, USER_B as never);
    expect(a.id).toBe("ws-a");
    expect(b.id).toBe("ws-b");
  });

  it("soft-deleted workspaces are invisible to resolution", async () => {
    const { prisma } = makeStore();
    await expect(resolveWorkspace(prisma as never, USER_A as never, "ws-a-dead")).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("unknown workspaceId is refused identically (no existence oracle split)", async () => {
    const { prisma } = makeStore();
    await expect(resolveWorkspace(prisma as never, USER_A as never, "ws-nope")).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe("TenantIsolationTestSuite — target ownership (§35/§39)", () => {
  it("assertTargetInOrg returns own target, 404s foreign and missing targets alike", async () => {
    const { prisma } = makeStore();
    // The stub target table resolves the relation filter via __orgId.
    await expect(assertTargetInOrg(prisma as never, USER_A as never, "t-a")).resolves.toMatchObject({ id: "t-a" });
    await expect(assertTargetInOrg(prisma as never, USER_A as never, "t-b")).rejects.toBeInstanceOf(NotFoundException);
    await expect(assertTargetInOrg(prisma as never, USER_A as never, "t-nope")).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe("TenantIsolationTestSuite — object-level matrix (§40)", () => {
  it("findings: list contains only own tenant rows; foreign detail/evidence 404", async () => {
    const { prisma } = makeStore();
    const c = new FindingsController(prisma as never, auditStub as never);
    const listA = await c.list(USER_A);
    expect(listA.items.map((i: Row) => i.id)).toEqual(["f-a"]);
    const listB = await c.list(USER_B);
    expect(listB.items.map((i: Row) => i.id)).toEqual(["f-b"]);
    await expect(c.get(USER_B, "f-a")).rejects.toBeInstanceOf(NotFoundException);
    await expect(c.evidence(USER_B, "f-a")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("findings: review mutation on a foreign finding 404s and writes nothing", async () => {
    const { prisma, findings } = makeStore();
    const c = new FindingsController(prisma as never, auditStub as never);
    await expect(c.review(USER_B, "f-a", { status: "FALSE_POSITIVE", notes: "cross-tenant attempt" } as never))
      .rejects.toBeInstanceOf(NotFoundException);
    expect(findings.find((f) => f.id === "f-a")!.status).toBe("OPEN");
  });

  it("reports: list/detail are tenant-bound; create against a foreign scan 404s (mass assignment, §36)", async () => {
    const { prisma } = makeStore();
    const c = new ReportsController(prisma as never, auditStub as never);
    const listA = await c.list(USER_A, {});
    expect(listA.items.map((i: Row) => i.id)).toEqual(["r-a"]);
    expect(listA.total).toBe(1);
    await expect(c.get(USER_B, "r-a")).rejects.toBeInstanceOf(NotFoundException);
    // Tenant B tries to bind a report to tenant A's scan id (…74000 is A's):
    await expect(c.create(USER_B, { scanId: "123e4567-e89b-12d3-a456-426614174000", format: "PDF" }))
      .rejects.toBeInstanceOf(NotFoundException);
    // A well-formed own-tenant create succeeds and is stamped with B's
    // workspace by the server — the client never supplies the tenant key:
    const created = await c.create(USER_B, { scanId: "123e4567-e89b-12d3-a456-426614174001", format: "PDF" });
    expect(created.workspaceId).toBe("ws-b");
  });
});
