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
 * Launch Safety A5 + DNS-rebinding hardening: the HTTP_FILE ownership
 * check fetches a URL built from a user-registered hostname. It must
 * pass the endpoint verdict (no loopback/private/link-local/metadata
 * hosts — by literal OR by resolution), must never follow a redirect,
 * and the fetch must be PINNED to the address that was validated —
 * the hostname is resolved exactly once, so a rebinding second
 * resolution can never steer the fetch into private space.
 */
describe("TargetsService HTTP_FILE verification fetch guard (A5)", () => {
  const challenge = "dsrclone-verify=abc123";
  const pinnedFetchMock = jest.fn();

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
    svc.pinnedFetch = pinnedFetchMock as never;
    return { svc, updates };
  }

  beforeEach(() => {
    pinnedFetchMock.mockReset();
    (dns.lookup as unknown as jest.Mock).mockReset();
  });

  it("never fetches a loopback literal target", async () => {
    const { svc } = makeSvc("127.0.0.1");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("PENDING");
    expect(pinnedFetchMock).not.toHaveBeenCalled();
  });

  it("never fetches a public name that resolves into private space", async () => {
    (dns.lookup as unknown as jest.Mock).mockResolvedValue([{ address: "10.0.0.5", family: 4 }]);
    const { svc } = makeSvc("sneaky.example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("PENDING");
    expect(pinnedFetchMock).not.toHaveBeenCalled();
  });

  it("treats a redirect as a failed check and does not follow it", async () => {
    (dns.lookup as unknown as jest.Mock).mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    pinnedFetchMock.mockResolvedValue({ ok: false, status: 302, text: "" });
    const { svc } = makeSvc("example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("PENDING");
    expect(pinnedFetchMock).toHaveBeenCalledTimes(1);
  });

  it("pins the fetch to the single validated resolution (no re-resolution / rebinding window)", async () => {
    const lookupMock = dns.lookup as unknown as jest.Mock;
    lookupMock.mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    pinnedFetchMock.mockResolvedValue({ ok: true, status: 200, text: `token: ${challenge}` });
    const { svc } = makeSvc("example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("VERIFIED");
    expect(lookupMock).toHaveBeenCalledTimes(1);
    expect(pinnedFetchMock).toHaveBeenCalledWith(
      "https://example.com/.well-known/dsrclone-verification.txt", "93.184.216.34", 4,
    );
  });

  it("verifies when the public host serves the challenge file", async () => {
    (dns.lookup as unknown as jest.Mock).mockResolvedValue([{ address: "93.184.216.34", family: 4 }]);
    pinnedFetchMock.mockResolvedValue({ ok: true, status: 200, text: `token: ${challenge}` });
    const { svc, updates } = makeSvc("example.com");
    const res = await svc.checkVerification(user, "t1", "v1");
    expect(res.status).toBe("VERIFIED");
    expect(updates.some((u) => u.model === "target" && u.data.status === "VERIFIED")).toBe(true);
  });
});

/**
 * Attestation declaration (2026-10-25): a MANUAL_APPROVAL check only
 * completes with an explicit declaration (guidelines read + "I have
 * permission" ticked); the declaration and the request's network
 * address are stored on the verification row, and the attestation
 * record is visible only to platform administrators.
 */
describe("TargetsService MANUAL_APPROVAL declaration", () => {
  function makeSvc() {
    const updates: Array<{ model: string; data: Record<string, unknown> }> = [];
    const prismaMock = {
      target: {
        findFirst: async () => ({ id: "t1", value: "example.com", workspaceId: "ws1" }),
        update: async (args: { data: Record<string, unknown> }) => { updates.push({ model: "target", data: args.data }); return {}; },
      },
      targetVerification: {
        findFirst: async () => ({
          id: "v1", targetId: "t1", method: "MANUAL_APPROVAL",
          expiresAt: new Date(Date.now() + 3600_000),
        }),
        findMany: async () => ([{
          id: "v1", targetId: "t1", method: "MANUAL_APPROVAL", status: "VERIFIED",
          attestationIp: "203.0.113.9", attestationGuidelinesVersion: "1",
          attestationAt: new Date(),
        }]),
        update: async (args: { data: Record<string, unknown> }) => { updates.push({ model: "verification", data: args.data }); return {}; },
      },
    };
    const svc = new TargetsService(prismaMock as never, { record: async () => undefined } as never);
    return { svc, updates };
  }

  it("refuses a MANUAL_APPROVAL check with no declaration", async () => {
    const { svc } = makeSvc();
    await expect(svc.checkVerification(user, "t1", "v1")).rejects.toThrow("declaration");
    await expect(svc.checkVerification(user, "t1", "v1", { declarationAccepted: false })).rejects.toThrow("declaration");
  });

  it("verifies with a declaration and stores the attestation record", async () => {
    const { svc, updates } = makeSvc();
    const res = await svc.checkVerification(user, "t1", "v1", { declarationAccepted: true, clientIp: "203.0.113.9" });
    expect(res.status).toBe("VERIFIED");
    const v = updates.find((u) => u.model === "verification");
    expect(v?.data.attestationIp).toBe("203.0.113.9");
    expect(v?.data.attestationGuidelinesVersion).toBe("1");
    expect(v?.data.attestationAt).toBeInstanceOf(Date);
  });

  it("strips the attestation record for non-admins, keeps it for platform admins", async () => {
    const { svc } = makeSvc();
    const rows = await svc.listVerifications(user, "t1");
    expect("attestationIp" in (rows[0] as Record<string, unknown>)).toBe(false);
    const adminRows = await svc.listVerifications({ ...user, isPlatformAdmin: true }, "t1");
    expect((adminRows[0] as Record<string, unknown>).attestationIp).toBe("203.0.113.9");
  });
});
