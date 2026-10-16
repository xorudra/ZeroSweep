import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import * as bcrypt from "bcryptjs";
import {
  base32Decode, buildSignedResponse, sha256Hex, totp,
} from "@dsrclone/security-sdk";

/** Minimal CBOR encoder for WebAuthn fixtures (mirrors the SDK spec). */
function cborEncode(value: unknown): Buffer {
  const head = (major: number, arg: number): Buffer => {
    const m = major << 5;
    if (arg < 24) return Buffer.from([m | arg]);
    if (arg < 256) return Buffer.from([m | 24, arg]);
    const b = Buffer.alloc(3); b[0] = m | 25; b.writeUInt16BE(arg, 1); return b;
  };
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") { const b = Buffer.from(value, "utf8"); return Buffer.concat([head(3, b.length), b]); }
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) return Buffer.concat([head(4, value.length), ...value.map(cborEncode)]);
  if (value instanceof Map) { const parts: Buffer[] = [head(5, value.size)]; for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v)); return Buffer.concat(parts); }
  throw new Error("unsupported CBOR fixture value");
}
import { AuthService } from "../auth/auth.service";
import { AuthFlowService } from "./auth-flow.service";
import { IdentityAuthController } from "./identity.controller";
import { SecretResolver } from "./secret-resolver";
import { SessionsService } from "./sessions/sessions.service";
import { MfaService } from "./mfa/mfa.service";
import { WebAuthnService } from "./webauthn/webauthn.service";
import { SsoService, type OidcTransport } from "./sso/sso.service";
import { ScimService } from "./scim/scim.service";
import { KeysService } from "./keys/keys.service";
import { GovernanceService } from "./governance/governance.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (same pattern as prior phase specs).          */
/* ------------------------------------------------------------------ */
type Row = Record<string, unknown> & { id: string };
let seq = 0;
function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    if ("not" in c) { if (value === c.not) return false; continue; }
    return false;
  }
  return true;
}
function makeTable(name: string) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      rows.push(row);
      return row;
    },
    async findUnique(args: { where: Record<string, unknown>; include?: Record<string, unknown> }) {
      const row = rows.find((r) => matches(r, args.where)) ?? null;
      return row ? attachInclude(row, args.include) : null;
    },
    async findFirst(args: { where?: Record<string, unknown>; include?: Record<string, unknown> } = {}) {
      const row = rows.find((r) => matches(r, args.where)) ?? null;
      return row ? attachInclude(row, args.include) : null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number } = {}) {
      const list = rows.filter((r) => matches(r, args.where));
      return args.take ? list.slice(0, args.take) : list;
    },
    async count(args: { where?: Record<string, unknown> } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
    async update({ where, data }: { where: Record<string, unknown>; data: Record<string, unknown> }) {
      const row = rows.find((r) => matches(r, where));
      if (!row) throw new Error(`row not found in ${name}`);
      Object.assign(row, data);
      return row;
    },
    async updateMany({ where, data }: { where?: Record<string, unknown>; data: Record<string, unknown> }) {
      let count = 0;
      for (const row of rows) if (matches(row, where)) { Object.assign(row, data); count += 1; }
      return { count };
    },
    async delete({ where }: { where: Record<string, unknown> }) {
      const idx = rows.findIndex((r) => matches(r, where));
      if (idx >= 0) rows.splice(idx, 1);
      return {};
    },
    async deleteMany({ where }: { where?: Record<string, unknown> } = {}) {
      let count = 0;
      for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i], where)) { rows.splice(i, 1); count += 1; }
      return { count };
    },
    async createMany({ data }: { data: Row[] }) { for (const d of data) await table.create({ data: d }); return { count: data.length }; },
  };
  return table;
}
const TABLES = ["user", "organization", "membership", "workspace", "workspaceMembership", "userSession", "authChallenge", "mfaMethod", "recoveryCode", "webAuthnCredential", "authenticationEvent", "enterpriseSsoProvider", "oidcProviderConfig", "samlProviderConfig", "samlAssertionConsumption", "organizationDomain", "organizationInvitation", "scimCredential", "scimGroupMapping", "scimExternalRecord", "serviceAccount", "apiKey", "organizationSecurityPolicy", "passwordPolicy", "breakGlassEnrollment", "accessReview", "accessReviewItem", "auditLog"];
let db: Record<string, ReturnType<typeof makeTable>>;
function attachInclude(row: Row, include?: Record<string, unknown>): Row {
  if (include?.memberships) {
    const spec = include.memberships as { where?: Record<string, unknown>; take?: number };
    const list = db.membership.rows.filter((m) => m.userId === row.id && matches(m, spec.where));
    return { ...row, memberships: spec.take ? list.slice(0, spec.take) : list };
  }
  return row;
}

function makeWorld() {
  db = {};
  for (const t of TABLES) db[t] = makeTable(t);
  const prisma = db as never;
  const auditRecords: Record<string, unknown>[] = [];
  const audit = { record: async (r: Record<string, unknown>) => { auditRecords.push(r); return r; } } as never;
  const jwt = { sign: (p: Record<string, unknown>) => `jwt.${Buffer.from(JSON.stringify(p)).toString("base64url")}` } as never;
  const secrets = new SecretResolver();
  const sessions = new SessionsService(prisma, audit);
  const mfa = new MfaService(prisma, audit, secrets);
  const webauthn = new WebAuthnService(prisma, audit);
  const transport: OidcTransport & { discoveryDoc: Record<string, unknown>; tokenIdToken: string | null; jwksDoc: { keys: never[] } } = {
    discoveryDoc: {}, tokenIdToken: null, jwksDoc: { keys: [] },
    async discovery() { return this.discoveryDoc; },
    async jwks() { return this.jwksDoc as never; },
    async token() { return { id_token: this.tokenIdToken ?? undefined }; },
  };
  const sso = new SsoService(prisma, audit, secrets, sessions, jwt, transport);
  const scim = new ScimService(prisma, audit);
  const keys = new KeysService(prisma, audit);
  const governance = new GovernanceService(prisma, audit);
  const auth = new AuthService(prisma, jwt, audit);
  const flow = new AuthFlowService(prisma, audit, auth, mfa, sessions, governance);
  return { prisma, auditRecords, sessions, mfa, webauthn, sso, scim, keys, governance, auth, flow, transport };
}

let userSeq = 0;
async function seedUser(orgId: string, email: string, role: string, password = "Correct-Horse-42!") {
  const id = `user-${++userSeq}`;
  await db.user.create({ data: { id, email, normalizedEmail: email.toLowerCase(), name: "Rudra", passwordHash: bcrypt.hashSync(password, 4), isActive: true, status: "ACTIVE" } as never });
  await db.membership.create({ data: { userId: id, organizationId: orgId, role, status: "ACTIVE" } as never });
  return { id, email, password };
}
async function seedOrg(id: string) {
  await db.organization.create({ data: { id, name: id, slug: id, status: "ACTIVE" } as never });
  return id;
}
const asUser = (id: string, email: string, orgId: string, role: string): RequestUser => ({ id, email, organizationId: orgId, role: role as RequestUser["role"] });

/* ------------------------------------------------------------------ */
describe("local login & sessions (§117, §118, §122, §123, §124)", () => {
  it("logs in with a bcrypt-verified password, mints a fresh hashed session each time", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const row = db.user.rows.find((r) => r.id === u.id)!;
    expect(row.passwordHash).not.toContain(u.password);
    const first = await w.auth.login({ email: u.email, password: u.password }) as { accessToken: string; sessionToken: string };
    expect(first.accessToken).toContain("jwt.");
    const stored = db.userSession.rows[0];
    expect(stored.tokenHash).not.toBe(first.sessionToken);
    expect(stored.tokenHash).toBe(createHash("sha256").update(first.sessionToken).digest("hex"));
    const second = await w.auth.login({ email: u.email, password: u.password }) as { sessionToken: string };
    expect(second.sessionToken).not.toBe(first.sessionToken); // fixation: never reused
    await expect(w.auth.login({ email: u.email, password: "WrongPass123!" })).rejects.toThrow(/Invalid email or password/);
    await expect(w.auth.login({ email: "ghost@example.com", password: "whatever123" })).rejects.toThrow(/Invalid email or password/);
  });

  it("revoked sessions stop validating; role changes apply at next validation (§124)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "ANALYST");
    const login = await w.auth.login({ email: u.email, password: u.password }) as { sessionToken: string; sessionId: string };
    const ctx1 = await w.sessions.validateSessionToken(login.sessionToken);
    expect(ctx1?.user.role).toBe("ANALYST");
    await db.membership.update({ where: { id: db.membership.rows[0].id }, data: { role: "VIEWER" } });
    const ctx2 = await w.sessions.validateSessionToken(login.sessionToken);
    expect(ctx2?.user.role).toBe("VIEWER");
    await w.sessions.revokeSession(asUser(u.id, u.email, "org-a", "ANALYST"), login.sessionId);
    await expect(w.sessions.validateSessionToken(login.sessionToken)).rejects.toThrow(/revoked/);
  });

  it("rate-limits repeated failures with the generic message (§22)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    for (let i = 0; i < 10; i++) await expect(w.auth.login({ email: u.email, password: "bad-pass-123" }, "203.0.113.9")).rejects.toThrow(/Invalid email or password/);
    await expect(w.auth.login({ email: u.email, password: "bad-pass-123" }, "203.0.113.9")).rejects.toMatchObject({ status: 429 });
  });
});

describe("MFA flows (§119, §120)", () => {
  it("challenge rotation inherits attempts + expiry; expired/exhausted challenges cannot rotate", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const ctrl = new IdentityAuthController(w.flow, w.mfa, w.webauthn, w.sessions, w.prisma, w.auth);
    const expires = new Date(Date.now() + 5 * 60_000);
    await db.authChallenge.create({ data: {
      userId: u.id, type: "MFA_TOTP", tokenHash: sha256Hex("rotation-fixture-token"),
      expiresAt: expires, attempts: 3, metadata: { organizationId: "org-a", role: "OWNER" },
    } as never });
    const rotated = await ctrl.rotateChallenge({ challengeToken: "rotation-fixture-token" });
    expect(rotated.challengeToken).toBeTruthy();
    const replacement = db.authChallenge.rows.find((r) => r.tokenHash === sha256Hex(rotated.challengeToken!))!;
    expect(replacement.attempts).toBe(3); // budget NOT reset
    expect(new Date(replacement.expiresAt as Date).getTime()).toBe(expires.getTime()); // window NOT extended
    // Attempt budget exhausted → rotation refused, no fresh challenge.
    await db.authChallenge.update({ where: { id: replacement.id }, data: { attempts: 5 } });
    expect(await ctrl.rotateChallenge({ challengeToken: rotated.challengeToken! })).toEqual({ challengeToken: null });
    // Expired → rotation refused.
    await db.authChallenge.create({ data: {
      userId: u.id, type: "MFA_TOTP", tokenHash: sha256Hex("expired-fixture-token"),
      expiresAt: new Date(Date.now() - 1_000), attempts: 0, metadata: { organizationId: "org-a", role: "OWNER" },
    } as never });
    expect(await ctrl.rotateChallenge({ challengeToken: "expired-fixture-token" })).toEqual({ challengeToken: null });
  });

  it("TOTP gates login, completes via challenge, and a replayed code is refused", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const me = asUser(u.id, u.email, "org-a", "OWNER");
    const enrollment = await w.mfa.enrollTotp(me) as { secret: string };
    const code = totp(base32Decode(enrollment.secret), Date.now()).code;
    await w.mfa.activateTotp(me, code);
    // Activating consumed step N; wait-free replay protection: login flow
    // uses a fresh code from the NEXT step window by advancing time.
    const login = await w.auth.login({ email: u.email, password: u.password }) as { mfaRequired?: boolean; challengeToken?: string };
    expect(login.mfaRequired).toBe(true);
    const nextCode = totp(base32Decode(enrollment.secret), Date.now() + 30_000).code;
    const done = await w.flow.verifyMfaChallenge(login.challengeToken!, { code: nextCode }) as { accessToken: string; sessionToken: string };
    expect(done.accessToken).toContain("jwt.");
    // Replay: a brand-new challenge, same code → refused.
    const login2 = await w.auth.login({ email: u.email, password: u.password }) as { challengeToken?: string };
    await expect(w.flow.verifyMfaChallenge(login2.challengeToken!, { code: nextCode })).rejects.toThrow(/Invalid email or password/);
  });

  it("recovery codes are single-use and shown once (§120)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const me = asUser(u.id, u.email, "org-a", "OWNER");
    const { codes } = await w.mfa.generateRecoveryCodes(me) as { codes: string[] };
    expect(db.recoveryCode.rows.every((r) => !codes.some((c) => (r.codeHash as string).includes(c)))).toBe(true);
    const login = await w.auth.login({ email: u.email, password: u.password }) as { challengeToken?: string; mfaRequired?: boolean };
    expect(login.mfaRequired).toBe(true);
    const done = await w.flow.verifyMfaChallenge(login.challengeToken!, { recoveryCode: codes[0] }) as { accessToken: string };
    expect(done.accessToken).toContain("jwt.");
    const login2 = await w.auth.login({ email: u.email, password: u.password }) as { challengeToken?: string };
    await expect(w.flow.verifyMfaChallenge(login2.challengeToken!, { recoveryCode: codes[0] })).rejects.toThrow();
  });
});

describe("passkeys (§121)", () => {
  const rpId = "localhost";
  const origin = "http://localhost:3000";
  function fixture() {
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
    const cose = cborEncode(new Map<unknown, unknown>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]])) as Buffer;
    const credentialId = Buffer.from("fixture-credential-id-0123456789");
    const authData = (flags: number, counter: number, attested: boolean) => {
      const rpHash = createHash("sha256").update(rpId).digest();
      const ctr = Buffer.alloc(4); ctr.writeUInt32BE(counter);
      if (!attested) return Buffer.concat([rpHash, Buffer.from([flags]), ctr]);
      const len = Buffer.alloc(2); len.writeUInt16BE(credentialId.length);
      return Buffer.concat([rpHash, Buffer.from([flags]), ctr, Buffer.alloc(16), len, credentialId, cose]);
    };
    return { privateKey, credentialId, authData };
  }

  it("registers and authenticates; counter regression (clone) is refused", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const me = asUser(u.id, u.email, "org-a", "OWNER");
    const fx = fixture();
    const regOpts = await w.webauthn.registrationOptions(me) as { challenge: string };
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge: regOpts.challenge, origin, crossOrigin: false }));
    const attestation = cborEncode(new Map<unknown, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", fx.authData(0x05 | 0x40, 0, true)]])) as Buffer;
    const registered = await w.webauthn.register(me, { challenge: regOpts.challenge, credentialId: fx.credentialId.toString("base64url"), attestationObject: attestation.toString("base64url"), clientDataJSON: clientData.toString("base64url"), transports: ["internal"] } as never);
    expect(registered.registered).toBe(true);
    const stored = db.webAuthnCredential.rows[0];
    expect(stored.publicKey as string).not.toContain("PRIVATE");
    expect(stored.credentialId as string).toBe(fx.credentialId.toString("base64url"));

    const attempt = async (counter: number) => {
      const opts = await w.webauthn.authenticationOptions(u.id) as { challenge: string };
      const cd = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: opts.challenge, origin, crossOrigin: false }));
      const ad = fx.authData(0x05, counter, false);
      const signed = Buffer.concat([ad, createHash("sha256").update(cd).digest()]);
      const signature = createSign("sha256").update(signed).sign({ key: fx.privateKey, dsaEncoding: "der" });
      return w.webauthn.authenticate(u.id, "org-a", { challenge: opts.challenge, credentialId: fx.credentialId.toString("base64url"), authenticatorData: ad.toString("base64url"), clientDataJSON: cd.toString("base64url"), signature: signature.toString("base64url") });
    };
    expect(await attempt(5)).toBe(true);
    expect(await attempt(5)).toBe(false); // counter did not increase → cloned authenticator
    expect(await attempt(9)).toBe(true);
  });
});

describe("OIDC SSO (§125, §126)", () => {
  const idp = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const attacker = generateKeyPairSync("rsa", { modulusLength: 2048 });
  function mintIdToken(claims: Record<string, unknown>, key = idp.privateKey): string {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "idp-1", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
    const sig = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(key, "base64url");
    return `${header}.${payload}.${sig}`;
  }
  const jwks = { keys: [{ ...(idp.publicKey.export({ format: "jwk" }) as Record<string, unknown>), kid: "idp-1" }] };

  async function setupOidc(w: ReturnType<typeof makeWorld>) {
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    process.env.TENANT_SECRET_OIDC_TEST = "fixture-client-secret";
    const provider = await w.sso.createProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), {
      type: "OIDC", name: "Fixture IdP", issuer: "https://idp.example.com", clientId: "dsr-client",
      clientSecretRef: "env:TENANT_SECRET_OIDC_TEST", jitEnabled: true,
    }) as { id: string };
    await w.sso.enrollBreakGlass(asUser(admin.id, admin.email, "org-a", "OWNER"), admin.id);
    await w.sso.updateProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), provider.id, { enabled: true });
    return { admin, providerId: provider.id };
  }

  it("completes a strict-validated login with JIT provisioning", async () => {
    const w = makeWorld();
    const { providerId } = await setupOidc(w);
    w.transport.discoveryDoc = { issuer: "https://idp.example.com", authorization_endpoint: "https://idp.example.com/auth", token_endpoint: "https://idp.example.com/token", jwks_uri: "https://idp.example.com/jwks" };
    const start = await w.sso.startOidcLogin("org-a", providerId, "https://app.example.com/callback") as { state: string };
    const nowSec = Math.floor(Date.now() / 1000);
    const nonce = (db.authChallenge.rows.find((r) => r.type === "OIDC_FLOW")!.metadata as { nonce: string }).nonce;
    w.transport.jwksDoc = jwks as never;
    w.transport.tokenIdToken = mintIdToken({ iss: "https://idp.example.com", aud: "dsr-client", sub: "idp-subject-1", email: "rudra@example.com", name: "Rudra", nonce, iat: nowSec, exp: nowSec + 600 });
    const result = await w.sso.oidcCallback("org-a", providerId, { code: "auth-code", state: start.state, redirectUri: "https://app.example.com/callback" }) as { accessToken: string };
    expect(result.accessToken).toContain("jwt.");
    const created = db.user.rows.find((r) => r.email === "rudra@example.com");
    expect(created).toBeTruthy();
    expect((created!.passwordHash as string).length).toBeGreaterThan(20); // unusable random password — SSO only
  });

  it("rejects forged-signature, wrong-audience and replayed-state callbacks", async () => {
    const w = makeWorld();
    const { providerId } = await setupOidc(w);
    const nowSec = Math.floor(Date.now() / 1000);
    w.transport.discoveryDoc = { issuer: "https://idp.example.com", authorization_endpoint: "https://idp.example.com/auth", token_endpoint: "https://idp.example.com/token", jwks_uri: "https://idp.example.com/jwks" };
    w.transport.jwksDoc = jwks as never;
    const start = await w.sso.startOidcLogin("org-a", providerId, "https://app.example.com/callback") as { state: string };
    const nonce = (db.authChallenge.rows.find((r) => r.type === "OIDC_FLOW" && !r.consumedAt)!.metadata as { nonce: string }).nonce;
    const base = { iss: "https://idp.example.com", aud: "dsr-client", sub: "s1", email: "rudra@example.com", nonce, iat: nowSec, exp: nowSec + 600 };
    w.transport.tokenIdToken = mintIdToken(base, attacker.privateKey);
    await expect(w.sso.oidcCallback("org-a", providerId, { code: "c", state: start.state, redirectUri: "https://app.example.com/callback" })).rejects.toThrow(/SSO login failed/);
    const start2 = await w.sso.startOidcLogin("org-a", providerId, "https://app.example.com/callback") as { state: string };
    const nonce2 = (db.authChallenge.rows.filter((r) => r.type === "OIDC_FLOW" && !r.consumedAt).pop()!.metadata as { nonce: string }).nonce;
    w.transport.tokenIdToken = mintIdToken({ ...base, aud: "other-app", nonce: nonce2 });
    await expect(w.sso.oidcCallback("org-a", providerId, { code: "c", state: start2.state, redirectUri: "https://app.example.com/callback" })).rejects.toThrow(/SSO login failed/);
    await expect(w.sso.oidcCallback("org-a", providerId, { code: "c", state: start2.state, redirectUri: "https://app.example.com/callback" })).rejects.toThrow(/SSO login failed/); // state single-use
  });

  it("reports NOT_CONFIGURED honestly when the secret reference does not resolve", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const provider = await w.sso.createProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), {
      type: "OIDC", name: "Unprovisioned", issuer: "https://idp.example.com", clientId: "dsr-client", clientSecretRef: "env:TENANT_SECRET_DEFINITELY_MISSING",
    }) as { id: string };
    const test = await w.sso.testProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), provider.id) as { status: string };
    expect(test.status).toBe("NOT_CONFIGURED");
  });
});

describe("SAML SSO (§127, §128)", () => {
  const idp = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const idpPem = idp.privateKey.export({ format: "pem", type: "pkcs8" }) as string;
  const idpCert = idp.publicKey.export({ format: "pem", type: "spki" }) as string;

  async function setupSaml(w: ReturnType<typeof makeWorld>) {
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const provider = await w.sso.createProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), {
      type: "SAML", name: "Fixture SAML", idpEntityId: "https://idp.example.com", ssoUrl: "https://idp.example.com/sso",
      spEntityId: "dsrclone-sp", certificate: idpCert, jitEnabled: true, acsUrl: "https://app.example.com/acs",
    }) as { id: string };
    await w.sso.enrollBreakGlass(asUser(admin.id, admin.email, "org-a", "OWNER"), admin.id);
    await w.sso.updateProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), provider.id, { enabled: true });
    return provider.id;
  }
  const fixtureFor = (requestId: string, overrides: Record<string, unknown> = {}) => buildSignedResponse({
    idpEntityId: "https://idp.example.com", spEntityId: "dsrclone-sp", acsUrl: "https://app.example.com/acs",
    inResponseTo: requestId, nameId: "rudra@example.com", attributes: { email: ["rudra@example.com"], displayName: ["Rudra"] },
    nowMs: Date.now(), privateKeyPem: idpPem, ...overrides,
  } as never);

  it("accepts a valid signed response once; replay and tampering are refused", async () => {
    const w = makeWorld();
    const providerId = await setupSaml(w);
    const start = await w.sso.startSamlLogin("org-a", providerId) as { requestId: string };
    const responseXml = fixtureFor(start.requestId);
    const result = await w.sso.samlAcs("org-a", providerId, { samlResponse: Buffer.from(responseXml).toString("base64"), relayState: start.requestId }) as { accessToken: string };
    expect(result.accessToken).toContain("jwt.");
    const start2 = await w.sso.startSamlLogin("org-a", providerId) as { requestId: string };
    void start2;
    await expect(w.sso.samlAcs("org-a", providerId, { samlResponse: Buffer.from(responseXml).toString("base64") })).rejects.toThrow(/SSO login failed/); // unsolicited (no live challenge) + assertion replay
    const start3 = await w.sso.startSamlLogin("org-a", providerId) as { requestId: string };
    const tampered = fixtureFor(start3.requestId).replace("Rudra", "Mallory");
    await expect(w.sso.samlAcs("org-a", providerId, { samlResponse: Buffer.from(tampered).toString("base64"), relayState: start3.requestId })).rejects.toThrow(/SSO login failed/);
  });

  it("rejects an assertion issued for a different recipient than the configured ACS URL", async () => {
    const w = makeWorld();
    const providerId = await setupSaml(w);
    const start = await w.sso.startSamlLogin("org-a", providerId) as { requestId: string };
    const foreign = fixtureFor(start.requestId, { acsUrl: "https://evil.example.com/acs" });
    await expect(w.sso.samlAcs("org-a", providerId, { samlResponse: Buffer.from(foreign).toString("base64"), relayState: start.requestId })).rejects.toThrow(/SSO login failed/);
  });

  it("JIT disabled: a pre-existing non-member user is NOT silently granted membership", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    await seedOrg("org-b");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const existing = await seedUser("org-b", "rudra@example.com", "MEMBER"); // global user, member of org-b only
    void existing;
    const provider = await w.sso.createProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), {
      type: "SAML", name: "No-JIT SAML", idpEntityId: "https://idp.example.com", ssoUrl: "https://idp.example.com/sso",
      spEntityId: "dsrclone-sp", certificate: idpCert, jitEnabled: false, acsUrl: "https://app.example.com/acs",
    }) as { id: string };
    await w.sso.enrollBreakGlass(asUser(admin.id, admin.email, "org-a", "OWNER"), admin.id);
    await w.sso.updateProvider(asUser(admin.id, admin.email, "org-a", "OWNER"), provider.id, { enabled: true });
    const start = await w.sso.startSamlLogin("org-a", provider.id) as { requestId: string };
    const responseXml = fixtureFor(start.requestId);
    await expect(w.sso.samlAcs("org-a", provider.id, { samlResponse: Buffer.from(responseXml).toString("base64"), relayState: start.requestId })).rejects.toThrow(/SSO login failed/);
    expect(db.membership.rows.some((m) => m.organizationId === "org-a" && m.userId === existing.id)).toBe(false);
  });
});

describe("domains & invitations (§129, §63–65)", () => {
  it("verifies a domain only when the DNS TXT matches the stored hash", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const me = asUser(admin.id, admin.email, "org-a", "OWNER");
    const started = await w.governance.startDomainVerification(me, "Example.com") as { id: string; dnsRecord: { value: string } };
    const token = started.dnsRecord.value.split("=")[1];
    await expect(w.governance.confirmDomainVerification(me, started.id, async () => [["dsrclone-site-verification=wrong"]])).rejects.toThrow(/not found/);
    const verified = await w.governance.confirmDomainVerification(me, started.id, async () => [[`dsrclone-site-verification=${token}`]]) as { status: string };
    expect(verified.status).toBe("VERIFIED");
  });

  it("invitations are single-use and create membership on acceptance", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const me = asUser(admin.id, admin.email, "org-a", "OWNER");
    const invite = await w.governance.createInvitation(me, { email: "new@example.com", role: "ANALYST" }) as { token: string };
    const accepted = await w.governance.acceptInvitation(invite.token, { name: "Rudra", password: "Brand-New-Pass-42!" }) as { accepted: boolean };
    expect(accepted.accepted).toBe(true);
    await expect(w.governance.acceptInvitation(invite.token, {})).rejects.toThrow(/invalid or already used/);
  });
});

describe("SCIM provisioning (§130, §131, §132)", () => {
  async function setupScim(w: ReturnType<typeof makeWorld>) {
    await seedOrg("org-a");
    await seedOrg("org-b");
    const adminA = await seedUser("org-a", "admin@example.com", "OWNER");
    const tokenA = await w.scim.createOrRotateToken("org-a", adminA.id) as { token: string };
    const tokenB = await w.scim.createOrRotateToken("org-b", "admin-b") as { token: string };
    return { adminA, tokenA: tokenA.token, tokenB: tokenB.token };
  }

  it("provisions, filters, maps roles only via approved mappings, deprovisions by disabling", async () => {
    const w = makeWorld();
    const { tokenA } = await setupScim(w);
    const auth = await w.scim.authenticate(`Bearer ${tokenA}`);
    expect(auth.organizationId).toBe("org-a");
    // Unmapped group → default VIEWER only (§131).
    const created = await w.scim.createUser("org-a", { userName: "rudra@example.com", displayName: "Rudra", groups: [{ display: "Domain Admins" }] }) as { id: string };
    let membership = db.membership.rows.find((m) => m.userId === created.id)!;
    expect(membership.role).toBe("VIEWER");
    // Approved mapping → role flows.
    await w.scim.createMapping("org-a", "admin", { externalGroup: "Domain Admins", organizationRole: "ADMIN" });
    const created2 = await w.scim.createUser("org-a", { userName: "second@example.com", groups: [{ display: "Domain Admins" }] }) as { id: string };
    membership = db.membership.rows.find((m) => m.userId === created2.id)!;
    expect(membership.role).toBe("ADMIN");
    // Filter evaluation (§130).
    const list = await w.scim.listUsers("org-a", 'userName eq "rudra@example.com"') as { totalResults: number };
    expect(list.totalResults).toBe(1);
    await expect(w.scim.listUsers("org-a", 'userName eq "x" or 1 eq 1')).rejects.toThrow(/Invalid SCIM filter/);
    // Deprovision: disable + revoke membership + sessions preserved as records (§69/§132).
    const login = await w.auth.login({ email: "second@example.com", password: "irrelevant" }).catch(() => null);
    void login;
    await w.scim.deactivateUser("org-a", created2.id);
    const userRow = db.user.rows.find((r) => r.id === created2.id)!;
    expect(userRow.isActive).toBe(false);
    expect(db.user.rows.some((r) => r.id === created2.id)).toBe(true); // never deleted
    expect(db.membership.rows.find((m) => m.userId === created2.id)!.status).toBe("REVOKED");
  });

  it("a SCIM token can never address another organization (§141)", async () => {
    const w = makeWorld();
    const { tokenA, tokenB } = await setupScim(w);
    const createdB = await w.scim.createUser("org-b", { userName: "b@example.com" }) as { id: string };
    const authA = await w.scim.authenticate(`Bearer ${tokenA}`);
    await expect(w.scim.getUser(authA.organizationId, createdB.id)).rejects.toThrow(/not found/);
    await expect(w.scim.authenticate(`Bearer ${tokenB}x`)).rejects.toThrow(/Invalid SCIM token/);
    await expect(w.scim.authenticate(undefined)).rejects.toThrow(/required/);
  });
});

describe("API keys & service accounts (§133–136)", () => {
  it("keys are shown once, hash-only at rest, scope-checked and revocable", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const me = asUser(u.id, u.email, "org-a", "OWNER");
    await expect(w.keys.createPersonalApiKey(me, { name: "bad", scopes: ["shell:execute"] })).rejects.toThrow(/Invalid API scopes/);
    const created = await w.keys.createPersonalApiKey(me, { name: "ci", scopes: ["findings:read"] }) as { plaintext: string; prefix: string };
    const row = db.apiKey.rows[0];
    expect(JSON.stringify(row)).not.toContain(created.plaintext);
    const ok = await w.keys.authenticateApiKey(created.plaintext, "findings:read");
    expect(ok.ok).toBe(true);
    const denied = await w.keys.authenticateApiKey(created.plaintext, "reports:create");
    expect(denied).toEqual({ ok: false, reason: "INSUFFICIENT_SCOPE" });
    await w.keys.revokeApiKey(me, row.id);
    const after = await w.keys.authenticateApiKey(created.plaintext, "findings:read");
    expect(after.ok).toBe(false);
  });

  it("service accounts are workspace-bound; foreign workspaces are refused (§136)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    await seedOrg("org-b");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const me = asUser(u.id, u.email, "org-a", "OWNER");
    await db.workspace.create({ data: { id: "ws-a", organizationId: "org-a", name: "A" } as never });
    await db.workspace.create({ data: { id: "ws-b", organizationId: "org-b", name: "B" } as never });
    await expect(w.keys.createServiceAccount(me, { name: "x", scopes: ["findings:read"], workspaceId: "ws-b" })).rejects.toThrow(/outside your organization/);
    const account = await w.keys.createServiceAccount(me, { name: "ci", scopes: ["reports:create"], workspaceId: "ws-a" }) as { id: string };
    const cred = await w.keys.createServiceAccountCredential(me, account.id, { name: "ci key" }) as { plaintext: string };
    const auth = await w.keys.authenticateApiKey(cred.plaintext, "reports:create");
    expect(auth.ok).toBe(true);
    if (auth.ok) expect(auth.workspaceId).toBe("ws-a");
    await w.keys.updateServiceAccount(me, account.id, { status: "DISABLED" });
    const after = await w.keys.authenticateApiKey(cred.plaintext, "reports:create");
    expect(after.ok).toBe(false);
  });
});

describe("break-glass & tenant isolation (§137, §141, §100)", () => {
  it("SSO enforcement blocks password login except enrolled break-glass admins", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const normal = await seedUser("org-a", "normal@example.com", "ANALYST");
    const glass = await seedUser("org-a", "glass@example.com", "OWNER");
    await db.organizationSecurityPolicy.create({ data: { organizationId: "org-a", ssoRequirement: "SSO_REQUIRED" } as never });
    await expect(w.auth.login({ email: normal.email, password: normal.password })).rejects.toThrow(/Single sign-on is required/);
    await db.breakGlassEnrollment.create({ data: { organizationId: "org-a", userId: glass.id, status: "ACTIVE" } as never });
    const login = await w.auth.login({ email: glass.email, password: glass.password }) as { accessToken: string };
    expect(login.accessToken).toContain("jwt.");
    expect(w.auditRecords.some((r) => r.action === "BREAK_GLASS_LOGIN")).toBe(true);
  });

  it("refuses to require SSO without a provider and recovery path (§100)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const me = asUser(admin.id, admin.email, "org-a", "OWNER");
    await expect(w.governance.updateSecurityPolicy(me, { ssoRequirement: "SSO_REQUIRED" })).rejects.toThrow(/no SSO provider/);
  });

  it("tenant isolation: org B sees nothing of org A (§141)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    await seedOrg("org-b");
    const a = await seedUser("org-a", "a@example.com", "OWNER");
    const b = await seedUser("org-b", "b@example.com", "OWNER");
    const loginA = await w.auth.login({ email: a.email, password: a.password }) as { sessionId: string };
    const membersB = await w.governance.listMembers(asUser(b.id, b.email, "org-b", "OWNER"));
    expect(membersB.map((m) => m.email)).toEqual(["b@example.com"]);
    await expect(w.sessions.revokeSession(asUser(b.id, b.email, "org-b", "OWNER"), loginA.sessionId)).rejects.toThrow(/not found/);
    const providersB = await w.sso.listProviders(asUser(b.id, b.email, "org-b", "OWNER"));
    expect(providersB).toEqual([]);
  });

  it("password reset rotates the password and revokes sessions (§110)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const login = await w.auth.login({ email: u.email, password: u.password }) as { sessionToken: string };
    const request = await w.flow.requestPasswordReset(u.email) as { message: string; resetToken?: string };
    expect(request.message).toContain("If an account exists");
    await w.flow.resetPassword(request.resetToken!, "Replacement-Pass-99!");
    await expect(w.sessions.validateSessionToken(login.sessionToken)).rejects.toThrow(/revoked/);
    const relogin = await w.auth.login({ email: u.email, password: "Replacement-Pass-99!" }) as { accessToken: string };
    expect(relogin.accessToken).toContain("jwt.");
    await expect(w.flow.resetPassword(request.resetToken!, "Another-Pass-100!")).rejects.toThrow(/invalid or expired/);
  });

  it("access review decisions execute revocation (§94–96)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const target = await seedUser("org-a", "target@example.com", "ADMIN");
    void target;
    const me = asUser(admin.id, admin.email, "org-a", "OWNER");
    const review = await w.governance.createAccessReview(me, { title: "Q4" }) as { id: string; itemCount: number };
    expect(review.itemCount).toBeGreaterThanOrEqual(2);
    const { items } = await w.governance.getAccessReview(me, review.id) as { items: { id: string; subjectType: string; subjectId: string }[] };
    const targetMembership = db.membership.rows.find((m) => m.userId === target.id)!;
    const item = items.find((i) => i.subjectType === "MEMBERSHIP" && i.subjectId === targetMembership.id)!;
    await w.governance.decideAccessReviewItem(me, review.id, item.id, "REVOKE");
    expect(db.membership.rows.find((m) => m.id === targetMembership.id)!.status).toBe("REVOKED");
  });
});

describe("audit remediation regressions (2026-10-16)", () => {
  it("admin MFA reset refuses foreign-organization targets (404) and revokes same-org sessions", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    await seedOrg("org-b");
    const adminA = await seedUser("org-a", "admin@example.com", "OWNER");
    const foreign = await seedUser("org-b", "foreign@example.com", "MEMBER");
    const local = await seedUser("org-a", "local@example.com", "MEMBER");
    await db.mfaMethod.create({ data: { userId: foreign.id, type: "TOTP", isActive: true } as never });
    const actorA = asUser(adminA.id, adminA.email, "org-a", "OWNER");
    await expect(w.mfa.adminResetMfa(actorA, foreign.id)).rejects.toThrow(/not found/i);
    expect(db.mfaMethod.rows.some((r) => r.userId === foreign.id)).toBe(true); // untouched
    const login = await w.auth.login({ email: local.email, password: local.password }) as { sessionToken: string };
    await db.mfaMethod.create({ data: { userId: local.id, type: "TOTP", isActive: true } as never });
    await w.mfa.adminResetMfa(actorA, local.id);
    expect(db.mfaMethod.rows.some((r) => r.userId === local.id)).toBe(false);
    await expect(w.sessions.validateSessionToken(login.sessionToken)).rejects.toThrow(/revoked/);
  });

  it("plain members cannot rotate/revoke or even list service-account API keys", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const owner = await seedUser("org-a", "owner@example.com", "OWNER");
    const member = await seedUser("org-a", "member@example.com", "MEMBER");
    const ownerCtx = asUser(owner.id, owner.email, "org-a", "OWNER");
    const memberCtx = asUser(member.id, member.email, "org-a", "MEMBER");
    const account = await w.keys.createServiceAccount(ownerCtx, { name: "ci", scopes: ["findings:read"] }) as { id: string };
    const cred = await w.keys.createServiceAccountCredential(ownerCtx, account.id, { name: "ci key" }) as { id: string };
    const memberList = await w.keys.listApiKeys(memberCtx) as { id: string }[];
    expect(memberList.some((k) => k.id === cred.id)).toBe(false);
    await expect(w.keys.rotateApiKey(memberCtx, cred.id)).rejects.toThrow(/MANAGE_SERVICE_ACCOUNTS/);
    await expect(w.keys.revokeApiKey(memberCtx, cred.id)).rejects.toThrow(/MANAGE_SERVICE_ACCOUNTS/);
    const rotated = await w.keys.rotateApiKey(ownerCtx, cred.id) as { plaintext: string };
    expect(rotated.plaintext).toBeTruthy(); // privileged rotation still works
  });

  it("SCIM deprovision in one org leaves a shared user's other org untouched", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    await seedOrg("org-b");
    const shared = await w.scim.createUser("org-a", { userName: "shared@example.com", displayName: "Shared" }) as { id: string };
    await db.membership.create({ data: { userId: shared.id, organizationId: "org-b", role: "MEMBER", status: "ACTIVE" } as never });
    await w.scim.deactivateUser("org-a", shared.id);
    const userRow = db.user.rows.find((r) => r.id === shared.id)!;
    expect(userRow.isActive).toBe(true); // still a member elsewhere — global row untouched
    expect(db.membership.rows.find((m) => m.userId === shared.id && m.organizationId === "org-a")!.status).toBe("REVOKED");
    expect(db.membership.rows.find((m) => m.userId === shared.id && m.organizationId === "org-b")!.status).toBe("ACTIVE");
  });

  it("refresh rotation is a compare-and-swap: replaying a rotated credential revokes the session family", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const u = await seedUser("org-a", "rudra@example.com", "OWNER");
    const login = await w.auth.login({ email: u.email, password: u.password }) as { sessionToken: string; sessionId: string };
    const rotated = await w.sessions.rotateSessionCredential(login.sessionId, login.sessionToken);
    expect(rotated.sessionToken).not.toBe(login.sessionToken);
    // Replay of the superseded credential: CAS miss → reuse → family revoked.
    await expect(w.sessions.rotateSessionCredential(login.sessionId, login.sessionToken)).rejects.toThrow(/reuse/);
    await expect(w.sessions.validateSessionToken(rotated.sessionToken)).rejects.toThrow(/revoked/);
    expect(db.authenticationEvent.rows.some((r) => r.eventType === "SESSION_TOKEN_REUSE_DETECTED")).toBe(true);
  });

  it("role change revokes the demoted member's live sessions (§124)", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const target = await seedUser("org-a", "target@example.com", "ADMIN");
    const login = await w.auth.login({ email: target.email, password: target.password }) as { sessionToken: string };
    await w.governance.setMembershipRole(asUser(admin.id, admin.email, "org-a", "OWNER"), target.id, "VIEWER");
    await expect(w.sessions.validateSessionToken(login.sessionToken)).rejects.toThrow(/revoked/);
  });

  it("SSO write sites reject platform env secret references and non-public issuers", async () => {
    const w = makeWorld();
    await seedOrg("org-a");
    const admin = await seedUser("org-a", "admin@example.com", "OWNER");
    const me = asUser(admin.id, admin.email, "org-a", "OWNER");
    await expect(w.sso.createProvider(me, {
      type: "OIDC", name: "Evil", issuer: "https://idp.example.com", clientId: "x", clientSecretRef: "env:JWT_SECRET",
    })).rejects.toThrow(/TENANT_SECRET/);
    await expect(w.sso.createProvider(me, {
      type: "OIDC", name: "Ssrf", issuer: "https://169.254.169.254", clientId: "x", clientSecretRef: "env:TENANT_SECRET_OK",
    })).rejects.toThrow(/ENDPOINT_BLOCKED|blocked/i);
    await expect(w.sso.createProvider(me, {
      type: "OIDC", name: "Http", issuer: "http://idp.example.com", clientId: "x", clientSecretRef: "env:TENANT_SECRET_OK",
    })).rejects.toThrow(/ENDPOINT_NOT_HTTPS/);
  });
});
