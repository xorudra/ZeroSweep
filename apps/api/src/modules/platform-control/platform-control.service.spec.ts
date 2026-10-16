import { BadRequestException, NotFoundException } from "@nestjs/common";
import { PlatformControlDataService } from "./platform-control.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Support-access regression: an operator must not be able to mint an
 * ACTIVE session by self-attesting tenantApproved in the create
 * request. Sessions start PENDING_APPROVAL and activate only through
 * approveSupportSession (the tenant-side approval, recording
 * approvedById).
 */
function makeSvc() {
  const sessions: any[] = [];
  let seq = 0;
  const prisma: any = {
    organization: { findUnique: async ({ where }: any) => (where.id === "org-1" ? { id: "org-1" } : null) },
    supportAccessSession: {
      create: async ({ data }: any) => { const row = { id: `s-${++seq}`, createdAt: new Date(), ...data }; sessions.push(row); return row; },
      findFirst: async ({ where }: any) => sessions.find((s) => s.id === where.id && s.organizationId === where.organizationId) ?? null,
      findUnique: async ({ where }: any) => sessions.find((s) => s.id === where.id) ?? null,
      update: async ({ where, data }: any) => { const row = sessions.find((s) => s.id === where.id); Object.assign(row, data); return row; },
      findMany: async () => sessions,
    },
    auditLog: { findMany: async () => auditRows },
  };
  const auditRows: any[] = [];
  const audit: any = { record: async (r: any) => { auditRows.push(r); } };
  return { svc: new PlatformControlDataService(prisma, audit), auditRows };
}

const input = { organizationId: "org-1", reason: "Investigating scan failures for ticket 42", scope: { areas: ["health"] }, expiresInHours: 4 };

describe("support access (§100–§103)", () => {
  it("create with tenantApproved:true still starts PENDING_APPROVAL and grants nothing", async () => {
    const { svc } = makeSvc();
    const session = await svc.createSupportSession({ id: "op-1" }, { ...input, tenantApproved: true });
    expect(session.status).toBe("PENDING_APPROVAL");
    expect(session.tenantApproved).toBe(false);
    expect(session.startedAt).toBeNull();
    await expect(svc.requireActiveSupportSession(session.id, "org-1")).rejects.toBeInstanceOf(BadRequestException);
  });

  it("only a tenant-side approval for the target org activates, recording approvedById + audit", async () => {
    const { svc, auditRows } = makeSvc();
    const session = await svc.createSupportSession({ id: "op-1" }, { ...input, tenantApproved: true });
    await expect(svc.approveSupportSession("org-2", session.id, "u-other-tenant")).rejects.toBeInstanceOf(NotFoundException);
    const approved = await svc.approveSupportSession("org-1", session.id, "u-tenant-owner");
    expect(approved.status).toBe("ACTIVE");
    expect(approved.approvedById).toBe("u-tenant-owner");
    expect(approved.tenantApproved).toBe(true);
    await expect(svc.requireActiveSupportSession(session.id, "org-1")).resolves.toBeTruthy();
    expect(auditRows.map((r) => r.action)).toContain("SUPPORT_ACCESS_APPROVED");
  });
});
