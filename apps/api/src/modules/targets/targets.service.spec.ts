import { promises as dns } from "node:dns";
import { TargetsService } from "./targets.service";

jest.mock("node:dns", () => {
  const actual = jest.requireActual("node:dns") as Record<string, unknown>;
  return { ...actual, promises: { ...(actual.promises as Record<string, unknown>), lookup: jest.fn() } };
});

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

/**
 * Launch Safety A5: the HTTP_FILE ownership check fetches a URL built
 * from a user-registered hostname. It must pass the endpoint verdict
 * (no loopback/private/link-local/metadata hosts — by literal OR by
 * resolution) and must never follow a redirect.
 */
describe("TargetsService HTTP_FILE verification fetch guard (A5)", () => {
  const challenge = "dsrclone-verify=abc123";
  const fetchMock = jest.fn();
  let originalFetch: typeof globalThis.fetch;

  function makeSvc(targetValue: string) {
    const updates: Array<{ model: string; data: Record<string, unknown> }> = [];
    const prismaMock = {
      target: {
        findFirst: async () => ({ id: "t1", value: targetValue, workspaceId: "ws1" }),
        update: async (args: { data: Record<string, unknown> }) => { updates.push({ model: "target", data: args.data }); return {}; },
      },
      targetVerification: {
        findFirst: async () => ({
          id: "v1", targetId: "t1", method: "HTTP_FILE", challenge,
          expiresAt: new Date(Date.now() + 3600_000),
        }),
        update: async (args: { data: Record<string, unknown> }) => { updates.push({ model: "verification", data: args.data }); return {}; },
      },
    };
    const svc = new TargetsService(prismaMock as never, { record: async () => undefined } as never);
    return { svc, updates };
  }

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as never;
    fetchMock.mockReset();
    (dns.lookup as unknown as jest.Mock).mockReset();
  });
  afterEach(() => { globalThis.fetch = originalFetch; });

  it("never fetches a loopback literal target", async () => {
    const { svc } = makeSvc("127.0.0.1");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("PENDING");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("never fetches a public name that resolves into private space", async () => {
    (dns.lookup as unknown as jest.Mock).mockResolvedValue([{ address: "10.0.0.5", family: 4 }]);
    const { svc } = makeSvc("sneaky.example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("PENDING");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("treats a redirect as a failed check and does not follow it", async () => {
    (dns.lookup as unknown as jest.Mock).mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    fetchMock.mockResolvedValue({ ok: false, status: 302, text: async () => "" });
    const { svc } = makeSvc("example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("PENDING");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
  });

  it("verifies when the public host serves the challenge file", async () => {
    (dns.lookup as unknown as jest.Mock).mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    fetchMock.mockResolvedValue({ ok: true, status: 200, text: async () => `token: ${challenge}` });
    const { svc, updates } = makeSvc("example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("VERIFIED");
    expect(updates.some((u) => u.model === "target" && u.data.status === "VERIFIED")).toBe(true);
  });
});
