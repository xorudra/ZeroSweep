import { TargetsService } from "./targets.service";

const user = { id: "u1", email: "a@b.c", organizationId: "org1", role: "OWNER" as const };

/** Organization isolation: every target query must be scoped through a
 *  workspace belonging to the caller's organization. */
describe("TargetsService tenant isolation", () => {
  it("scopes list queries to a workspace inside the caller's organization", async () => {
    const calls: Array<{ args: unknown }> = [];
    const prismaMock = {
      workspace: { findFirst: async (args: unknown) => { calls.push({ args }); return { id: "ws1", organizationId: "org1" }; } },
      target: {
        findMany: async () => [],
        count: async (args: { where: { workspaceId: string } }) => { expect(args.where.workspaceId).toBe("ws1"); return 0; },
      },
    };
    const svc = new TargetsService(prismaMock as never, { record: async () => undefined } as never);
    const res = await svc.list(user, {});
    expect(res.total).toBe(0);
    expect(JSON.stringify(calls[0]?.args)).toContain("org1");
  });
  it("rejects access when the workspace is outside the caller's organization", async () => {
    const prismaMock = {
      workspace: { findFirst: async () => null },
      target: { findMany: async () => [], count: async () => 0 },
    };
    const svc = new TargetsService(prismaMock as never, { record: async () => undefined } as never);
    await expect(svc.list(user, {})).rejects.toThrow();
  });
});
