import { Controller, Get, Module, type INestApplication } from "@nestjs/common";
import { APP_GUARD, NestFactory } from "@nestjs/core";
import { JwtModule, JwtService } from "@nestjs/jwt";
import { PassportModule } from "@nestjs/passport";
import { loadEnv } from "@dsrclone/config";
import { PRISMA } from "../../prisma/prisma.module";
import { JwtAuthGuard } from "../../common/guards/jwt-auth.guard";
import { AuditService } from "../audit/audit.service";
import { QueueService } from "../../queue/queue.service";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { JwtStrategy } from "./jwt.strategy";
import { IdentityAuthController } from "../identity/identity.controller";
import { AuthFlowService } from "../identity/auth-flow.service";
import { MfaService } from "../identity/mfa/mfa.service";
import { WebAuthnService } from "../identity/webauthn/webauthn.service";
import { SessionsService } from "../identity/sessions/sessions.service";

/**
 * Launch Safety A7 — session-linked JWTs, proven end-to-end over HTTP
 * with the real guard, strategy, services and controllers, backed by an
 * in-memory Prisma fake (same pattern as the phase specs):
 * - login/register mint a JWT whose `sid` names the server-side session,
 *   plus the HttpOnly refresh cookie;
 * - a guarded route answers 200 only while that session is live —
 *   revoked, idle-expired or absolute-expired sessions are 401, and a
 *   JWT with no `sid` is 401;
 * - POST /auth/refresh validates the cookie and ROTATES the credential
 *   (the old cookie dies, the new one works);
 * - logout revokes the session, so the already-issued JWT AND the
 *   refresh cookie both fail afterwards. Password reset/change revoke
 *   sessions through the same updateMany (§110/§111), so this is also
 *   the property that makes their revocation reach live JWTs.
 */

type Row = Record<string, unknown> & { id: string };

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    return false;
  }
  return true;
}

let seq = 0;
function makeTable() {
  const rows: Row[] = [];
  return {
    rows,
    create: async ({ data }: { data: Record<string, unknown> }) => {
      const now = new Date();
      const row: Row = {
        id: `row-${++seq}`,
        createdAt: now, updatedAt: now, lastSeenAt: now, revokedAt: null,
        ...data,
      } as Row;
      rows.push(row);
      return row;
    },
    findUnique: async ({ where, include }: { where: Record<string, unknown>; include?: Record<string, unknown> }) => {
      const row = rows.find((r) => matches(r, where)) ?? null;
      if (row && include?.memberships) {
        const spec = (include.memberships as { where?: Record<string, unknown>; take?: number });
        const all = membershipRows.filter((m) => m.userId === row.id && matches(m, spec.where ?? {}));
        return { ...row, memberships: spec.take ? all.slice(0, spec.take) : all };
      }
      return row;
    },
    findFirst: async ({ where }: { where?: Record<string, unknown> } = {}) => rows.find((r) => matches(r, where ?? {})) ?? null,
    findMany: async ({ where, orderBy, take }: { where?: Record<string, unknown>; orderBy?: Record<string, string>; take?: number } = {}) => {
      let out = rows.filter((r) => matches(r, where ?? {}));
      if (orderBy) {
        const [key, dir] = Object.entries(orderBy)[0] as [string, string];
        out = [...out].sort((a, b) => {
          const av = (a[key] as Date)?.getTime?.() ?? (a[key] as number);
          const bv = (b[key] as Date)?.getTime?.() ?? (b[key] as number);
          return dir === "desc" ? bv - av : av - bv;
        });
      }
      return take ? out.slice(0, take) : out;
    },
    update: async ({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) => {
      const row = rows.find((r) => matches(r, where));
      if (!row) throw new Error("record not found");
      Object.assign(row, data);
      return row;
    },
    updateMany: async ({ where, data }: { where?: Record<string, unknown>; data: Record<string, unknown> }) => {
      let count = 0;
      for (const row of rows) if (matches(row, where ?? {})) { Object.assign(row, data); count += 1; }
      return { count };
    },
    count: async ({ where }: { where?: Record<string, unknown> } = {}) => rows.filter((r) => matches(r, where ?? {})).length,
  };
}

const membershipTable = makeTable();
let membershipRows: Row[] = membershipTable.rows;

function makeFakePrisma() {
  const tables = {
    user: makeTable(),
    organization: makeTable(),
    membership: membershipTable,
    workspace: makeTable(),
    userSession: makeTable(),
    organizationSecurityPolicy: makeTable(),
    enterpriseSsoProvider: makeTable(),
    mfaMethod: makeTable(),
    webAuthnCredential: makeTable(),
    recoveryCode: makeTable(),
    authenticationEvent: makeTable(),
    auditLog: makeTable(),
    authChallenge: makeTable(),
  };
  membershipRows = tables.membership.rows;
  // Prisma column defaults the services rely on but never set explicitly.
  const userCreate = tables.user.create;
  tables.user.create = async (args: { data: Record<string, unknown> }) =>
    userCreate({ data: { isActive: true, status: "ACTIVE", ...args.data } });
  const membershipCreate = tables.membership.create;
  tables.membership.create = async (args: { data: Record<string, unknown> }) =>
    membershipCreate({ data: { status: "ACTIVE", ...args.data } });
  return tables;
}

@Controller("probe")
class ProbeController {
  @Get()
  probe() { return { ok: true }; }
}

const EMAIL = "a7-user@example.com";
const PASSWORD = "a-strong-password";

describe("A7 session-linked JWTs (guard + refresh + logout)", () => {
  let app: INestApplication;
  let base: string;
  let fake: ReturnType<typeof makeFakePrisma>;
  let jwt: JwtService;
  let sessions: SessionsService;
  let userId: string;
  let organizationId: string;

  const registerBody = {
    name: "A7 User", email: EMAIL, password: PASSWORD, organizationName: "A7 Org",
    termsAccepted: true, termsVersion: "2026-10-10",
  };

  async function login() {
    const res = await fetch(`${base}/auth/login`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: EMAIL, password: PASSWORD }),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { accessToken: string; sessionToken?: string; sessionId: string };
    // The session credential must NOT appear in the JSON body — it
    // travels only in the HttpOnly Set-Cookie header. Tests obtain it
    // from the cookie, exactly like the web client does.
    expect(body.sessionToken).toBeUndefined();
    const setCookie = res.headers.getSetCookie().find((c) => c.startsWith("dsrclone_session=")) ?? "";
    const cookie = setCookie.split(";")[0] as string;
    const sessionToken = decodeURIComponent(cookie.slice("dsrclone_session=".length));
    return { ...body, sessionToken, cookie };
  }

  const probe = (token: string) => fetch(`${base}/probe`, { headers: { authorization: `Bearer ${token}` } });
  const refresh = (cookie: string) => fetch(`${base}/auth/refresh`, { method: "POST", headers: { cookie } });

  beforeAll(async () => {
    fake = makeFakePrisma();
    // @nestjs/testing is not a workspace dependency — boot a real Nest
    // application on a hand-defined module with the production wiring
    // (same guard, strategy, services and controllers), fake Prisma only.
    @Module({
      imports: [
        PassportModule,
        JwtModule.register({ secret: loadEnv().JWT_SECRET, signOptions: { expiresIn: "1h" } }),
      ],
      controllers: [AuthController, IdentityAuthController, ProbeController],
      providers: [
        { provide: PRISMA, useValue: fake },
        { provide: QueueService, useValue: { enqueuePlaceholder: async () => true } },
        { provide: AuthFlowService, useValue: {} },
        { provide: MfaService, useValue: {} },
        { provide: WebAuthnService, useValue: {} },
        AuditService, AuthService, SessionsService, JwtStrategy,
        { provide: APP_GUARD, useClass: JwtAuthGuard },
      ],
    })
    class A7TestModule {}
    app = await NestFactory.create(A7TestModule, { logger: false });
    await app.listen(0);
    const address = app.getHttpServer().address() as { port: number };
    base = `http://127.0.0.1:${address.port}`;
    jwt = app.get(JwtService);
    sessions = app.get(SessionsService);

    const res = await fetch(`${base}/auth/register`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(registerBody),
    });
    expect(res.status).toBe(201);
    const body = (await res.json()) as { user: { id: string }; organization: { id: string }; accessToken: string; sessionId: string };
    userId = body.user.id;
    organizationId = body.organization.id;
    // Registration itself mints a session-linked JWT that passes the guard.
    expect(body.accessToken).toBeTruthy();
    expect((await probe(body.accessToken)).status).toBe(200);
  }, 120_000);

  afterAll(async () => { await app.close(); });

  it("login binds the JWT to the session (sid) and the guarded route answers 200", async () => {
    const { accessToken, sessionId, cookie } = await login();
    expect(cookie).toContain("dsrclone_session=");
    const payload = JSON.parse(Buffer.from(accessToken.split(".")[1] as string, "base64url").toString("utf8")) as { sid?: string };
    expect(payload.sid).toBe(sessionId);
    expect((await probe(accessToken)).status).toBe(200);
  });

  it("rejects a JWT with no session claim", async () => {
    const bare = jwt.sign({ sub: userId, email: EMAIL, organizationId, role: "OWNER" });
    expect((await probe(bare)).status).toBe(401);
  });

  it("rejects the JWT as soon as its session is revoked", async () => {
    const { accessToken, sessionId } = await login();
    expect((await probe(accessToken)).status).toBe(200);
    await sessions.revokeSession({ id: userId, email: EMAIL, organizationId, role: "OWNER" }, sessionId);
    expect((await probe(accessToken)).status).toBe(401);
  });

  it("refresh rotates the cookie credential: old cookie dies, new cookie works, JWT stays session-bound", async () => {
    const first = await login();
    const res1 = await refresh(first.cookie);
    expect(res1.status).toBe(201);
    const body1 = (await res1.json()) as { accessToken: string; sessionId: string };
    expect(body1.sessionId).toBe(first.sessionId);
    const setCookie2 = res1.headers.getSetCookie().find((c) => c.startsWith("dsrclone_session=")) ?? "";
    const cookie2 = setCookie2.split(";")[0] as string;
    expect(cookie2).not.toBe(first.cookie);
    expect(setCookie2).toContain("HttpOnly");
    // The rotated JWT works, the SPENT cookie is dead, the fresh one works.
    expect((await probe(body1.accessToken)).status).toBe(200);
    expect((await refresh(first.cookie)).status).toBe(401);
    expect((await refresh(cookie2)).status).toBe(201);
  });

  it("logout revokes the session: the old JWT and the refresh cookie both fail", async () => {
    const { accessToken, cookie } = await login();
    const out = await fetch(`${base}/auth/logout`, {
      method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({}),
    });
    expect(out.status).toBe(201);
    const cleared = out.headers.getSetCookie().find((c) => c.startsWith("dsrclone_session=")) ?? "";
    expect(cleared).toContain("Max-Age=0");
    expect((await probe(accessToken)).status).toBe(401);
    expect((await refresh(cookie)).status).toBe(401);
  });

  it("rejects the JWT once the session is idle-expired", async () => {
    const { accessToken, sessionId } = await login();
    const row = fake.userSession.rows.find((r) => r.id === sessionId) as Row;
    row.lastSeenAt = new Date(Date.now() - 31 * 60_000);
    expect((await probe(accessToken)).status).toBe(401);
  });

  it("rejects the JWT once the session passes its absolute lifetime", async () => {
    const { accessToken, sessionId } = await login();
    const row = fake.userSession.rows.find((r) => r.id === sessionId) as Row;
    row.createdAt = new Date(Date.now() - 721 * 60_000);
    row.lastSeenAt = new Date();
    expect((await probe(accessToken)).status).toBe(401);
  });
});
