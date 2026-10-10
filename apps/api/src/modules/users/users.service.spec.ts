import * as bcrypt from "bcryptjs";
import { BadRequestException, NotFoundException, UnauthorizedException } from "@nestjs/common";
import { UsersService } from "./users.service";

const caller = { id: "u1", email: "a@b.c", organizationId: "org1", role: "OWNER" as const };
const CORRECT = "correct-horse-battery";

function makeService(overrides: {
  ownerCount?: number;
  memberships?: Array<{ organizationId: string; role: string; status: string }>;
  profileDeletedAt?: Date | null;
} = {}) {
  const calls = {
    userUpdate: [] as Array<{ where: unknown; data: Record<string, unknown> }>,
    membershipUpdateMany: [] as Array<unknown>,
    sessionUpdateMany: [] as Array<unknown>,
    audit: [] as Array<{ action: string; actorId?: string }>,
  };
  const passwordHash = bcrypt.hashSync(CORRECT, 4);
  const prismaMock = {
    user: {
      findUnique: async ({ select }: { select?: Record<string, boolean> }) => {
        if (select) {
          // export profile read
          return {
            id: "u1", email: "a@b.c", name: "Rudra", isActive: true, status: "ACTIVE",
            emailVerifiedAt: null, termsAcceptedAt: new Date(), termsVersion: "2026-10-10",
            lastLoginAt: null, createdAt: new Date(), updatedAt: new Date(),
            deletedAt: overrides.profileDeletedAt ?? null,
          };
        }
        return { id: "u1", email: "a@b.c", passwordHash, deletedAt: null };
      },
      update: async (args: { where: unknown; data: Record<string, unknown> }) => {
        calls.userUpdate.push(args);
        return { id: "u1", ...args.data };
      },
    },
    membership: {
      findMany: async ({ where }: { where: { userId?: string; status?: string } }) => {
        if (where.status === "ACTIVE" || overrides.memberships) {
          return overrides.memberships ?? [{ organizationId: "org1", role: "MEMBER", status: "ACTIVE" }];
        }
        return [{ organizationId: "org1", role: "MEMBER", status: "ACTIVE", organization: { id: "org1", name: "Org", slug: "org" } }];
      },
      count: async () => overrides.ownerCount ?? 2,
      updateMany: async (args: unknown) => { calls.membershipUpdateMany.push(args); return { count: 1 }; },
    },
    userSession: {
      findMany: async () => [{ id: "s1", organizationId: "org1" }],
      updateMany: async (args: unknown) => { calls.sessionUpdateMany.push(args); return { count: 1 }; },
    },
    auditLog: {
      findMany: async () => [{ id: "a1", action: "LOGIN" }],
    },
  };
  const auditMock = {
    record: async (entry: { action: string; actorId?: string }) => { calls.audit.push(entry); },
  };
  const svc = new UsersService(prismaMock as never, auditMock as never);
  return { svc, calls };
}

describe("UsersService.deleteMe (F28 self-service account deletion)", () => {
  it("rejects a wrong password and changes nothing", async () => {
    const { svc, calls } = makeService();
    await expect(svc.deleteMe(caller, { password: "wrong-password" })).rejects.toBeInstanceOf(UnauthorizedException);
    expect(calls.userUpdate).toHaveLength(0);
    expect(calls.membershipUpdateMany).toHaveLength(0);
    expect(calls.sessionUpdateMany).toHaveLength(0);
  });

  it("blocks the sole owner of an organization with a clear error", async () => {
    const { svc, calls } = makeService({
      memberships: [{ organizationId: "org1", role: "OWNER", status: "ACTIVE" }],
      ownerCount: 1,
    });
    await expect(svc.deleteMe(caller, { password: CORRECT })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.deleteMe(caller, { password: CORRECT })).rejects.toThrow(/only owner/);
    expect(calls.userUpdate).toHaveLength(0);
  });

  it("anonymizes the account, revokes sessions and removes memberships", async () => {
    const { svc, calls } = makeService({
      memberships: [
        { organizationId: "org1", role: "MEMBER", status: "ACTIVE" },
        { organizationId: "org2", role: "OWNER", status: "ACTIVE" },
      ],
      ownerCount: 2,
    });
    const res = await svc.deleteMe(caller, { password: CORRECT });
    expect(res.deleted).toBe(true);
    expect(calls.membershipUpdateMany).toHaveLength(1);
    expect(calls.sessionUpdateMany).toHaveLength(1);
    expect(calls.userUpdate).toHaveLength(1);
    const data = calls.userUpdate[0]!.data;
    expect(data.email).toBe("deleted-u1@deleted.invalid");
    expect(data.name).toBe("Deleted user");
    expect(data.isActive).toBe(false);
    expect(data.status).toBe("DEACTIVATED");
    expect(data.deletedAt).toBeInstanceOf(Date);
    // The stored credential is a fresh hash of a throwaway secret, never the old one.
    expect(typeof data.passwordHash).toBe("string");
    expect(await bcrypt.compare(CORRECT, data.passwordHash as string)).toBe(false);
    expect(calls.audit.map((a) => a.action)).toContain("USER_ACCOUNT_DELETED");
  });

  it("cannot be aimed at another user: a smuggled target id is rejected by the strict schema", async () => {
    const { svc, calls } = makeService();
    await expect(
      svc.deleteMe(caller, { password: CORRECT, userId: "someone-else" } as never),
    ).rejects.toBeInstanceOf(BadRequestException);
    expect(calls.userUpdate).toHaveLength(0);
  });
});

describe("UsersService.exportMe (F29 personal data export)", () => {
  it("returns only the caller's own data and never credential material", async () => {
    const { svc, calls } = makeService();
    const res = await svc.exportMe(caller);
    expect(res.profile).toMatchObject({ id: "u1", email: "a@b.c", termsVersion: "2026-10-10" });
    expect(JSON.stringify(res)).not.toContain("passwordHash");
    expect(JSON.stringify(res)).not.toContain("tokenHash");
    expect(res.memberships).toHaveLength(1);
    expect(res.sessions).toHaveLength(1);
    expect(res.auditTrail).toHaveLength(1);
    expect(calls.audit.map((a) => a.action)).toContain("USER_DATA_EXPORTED");
  });

  it("scopes every read to the caller's id", async () => {
    const wheres: Array<Record<string, unknown>> = [];
    const prismaMock = {
      user: {
        findUnique: async ({ where }: { where: Record<string, unknown> }) => {
          wheres.push(where);
          return {
            id: "u1", email: "a@b.c", name: "Rudra", isActive: true, status: "ACTIVE",
            emailVerifiedAt: null, termsAcceptedAt: null, termsVersion: null,
            lastLoginAt: null, createdAt: new Date(), updatedAt: new Date(), deletedAt: null,
          };
        },
      },
      membership: { findMany: async ({ where }: { where: Record<string, unknown> }) => { wheres.push(where); return []; } },
      userSession: { findMany: async ({ where }: { where: Record<string, unknown> }) => { wheres.push(where); return []; } },
      auditLog: { findMany: async ({ where }: { where: Record<string, unknown> }) => { wheres.push(where); return []; } },
    };
    const svc = new UsersService(prismaMock as never, { record: async () => undefined } as never);
    await svc.exportMe(caller);
    expect(wheres).toEqual([
      { id: "u1" },
      { userId: "u1" },
      { userId: "u1" },
      { actorId: "u1" },
    ]);
  });

  it("refuses a deleted account", async () => {
    const { svc } = makeService({ profileDeletedAt: new Date() });
    await expect(svc.exportMe(caller)).rejects.toBeInstanceOf(NotFoundException);
  });
});
