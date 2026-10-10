import { HttpException } from "@nestjs/common";
import { AuthService } from "./auth.service";

const VALID = {
  email: "new@example.com",
  password: "a-strong-password",
  name: "New User",
  organizationName: "New Org",
  termsAccepted: true,
  termsVersion: "2026-10-10",
};

function makeService() {
  const created: { userData?: Record<string, unknown> } = {};
  const prismaMock = {
    user: {
      findUnique: async () => null,
      create: async (args: { data: Record<string, unknown> }) => {
        created.userData = args.data;
        return { id: "u1", email: args.data.email, name: args.data.name, isPlatformAdmin: false };
      },
      update: async () => ({}),
    },
    organization: { create: async () => ({ id: "org1", name: "New Org" }) },
    membership: { create: async () => ({ id: "m1" }) },
    workspace: { create: async () => ({ id: "ws1" }) },
    userSession: { create: async () => ({ id: "s1" }) },
    authenticationEvent: { create: async () => ({}) },
  };
  const jwtMock = { sign: () => "token" };
  const auditMock = { record: async () => undefined };
  const svc = new AuthService(prismaMock as never, jwtMock as never, auditMock as never);
  return { svc, created };
}

describe("AuthService.register consent record (F26)", () => {
  it("persists the accepted Terms/Privacy version and timestamp on the user row", async () => {
    const { svc, created } = makeService();
    await svc.register(VALID, "203.0.113.9");
    expect(created.userData?.termsVersion).toBe("2026-10-10");
    expect(created.userData?.termsAcceptedAt).toBeInstanceOf(Date);
  });

  it("refuses registration without explicit terms acceptance", async () => {
    const { svc, created } = makeService();
    const { termsAccepted: _omit, ...withoutAcceptance } = VALID;
    await expect(svc.register(withoutAcceptance, "203.0.113.9")).rejects.toThrow();
    await expect(svc.register({ ...VALID, termsAccepted: false }, "203.0.113.9")).rejects.toThrow();
    expect(created.userData).toBeUndefined();
  });

  it("refuses registration without a terms version", async () => {
    const { svc } = makeService();
    const { termsVersion: _omit, ...withoutVersion } = VALID;
    await expect(svc.register(withoutVersion, "203.0.113.9")).rejects.toThrow();
  });
});

describe("AuthService registration rate limit keying (A10)", () => {
  it("caps attempts per client IP — one IP's flood does not consume another's budget", async () => {
    const { svc } = makeService();
    // 10 registrations from one IP are allowed (the §22 cap)…
    for (let i = 0; i < 10; i++) {
      await svc.register({ ...VALID, email: `u${i}@example.com` }, "198.51.100.7");
    }
    // …the 11th from the SAME ip is refused…
    await expect(svc.register(VALID, "198.51.100.7")).rejects.toBeInstanceOf(HttpException);
    // …while a different client IP still has its own budget. Before the
    // A10 fix every hosted caller collapsed into the shared edge IP, so
    // this call would have been refused too.
    await expect(svc.register({ ...VALID, email: "other@example.com" }, "203.0.113.9")).resolves.toBeDefined();
  }, 60_000);
});
