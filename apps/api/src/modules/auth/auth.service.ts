import { ConflictException, ForbiddenException, HttpException, HttpStatus, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { JwtService } from "@nestjs/jwt";
import * as bcrypt from "bcryptjs";
import { loginSchema, registerSchema } from "@dsrclone/validation";
import {
  GENERIC_AUTH_ERROR, isPrivilegedOrgRole, normalizeEmail, randomToken, rateLimitDecision, sha256Hex, type AttemptBucket,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { parseOrThrow } from "../../common/parse";
import { AuditService } from "../audit/audit.service";

/**
 * Local password authentication, extended by Prompt 23 WITHOUT breaking the
 * established register/login contract:
 * - Generic failure messages (§23) — never reveal which factor failed.
 * - Login/reset/MFA attempts are rate-limited by account+IP buckets (§22).
 * - When organization policy or enrollment requires MFA, login returns a
 *   challenge instead of a token; completion happens in the identity
 *   module's MFA verify endpoint (§24–28).
 * - When SSO is enforced, password login is refused AFTER password
 *   verification — except enrolled break-glass admins (§58/59), whose use
 *   is audited and alerted.
 * - Every successful login mints a BRAND-NEW server-side session (§41/122)
 *   and returns its opaque token alongside the platform JWT.
 */
@Injectable()
export class AuthService {
  private readonly attempts: AttemptBucket[] = [];

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly jwt: JwtService,
    private readonly audit: AuditService,
  ) {}

  /** Registration creates the user + their first organization, OWNER membership
   *  and a default workspace — the multi-tenant root. Passwords are bcrypt-hashed. */
  async register(raw: unknown) {
    const data = parseOrThrow(registerSchema, raw);
    const normalizedEmail = normalizeEmail(data.email);
    const existing = await this.prisma.user.findUnique({ where: { email: data.email } });
    if (existing) throw new ConflictException("An account with this email already exists");
    const passwordHash = await bcrypt.hash(data.password, 12);
    const slug = data.organizationName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + "-" + Math.random().toString(36).slice(2, 8);
    const user = await this.prisma.user.create({ data: { email: data.email, normalizedEmail, name: data.name, passwordHash } });
    const org = await this.prisma.organization.create({ data: { name: data.organizationName, slug } });
    await this.prisma.membership.create({ data: { userId: user.id, organizationId: org.id, role: "OWNER", joinedAt: new Date() } });
    const workspace = await this.prisma.workspace.create({ data: { organizationId: org.id, name: "Default Workspace" } });
    await this.audit.record({ actorId: user.id, organizationId: org.id, workspaceId: workspace.id, action: "REGISTER", resourceType: "User", resourceId: user.id });
    const session = await this.createSession(user.id as string, org.id as string, "AAL1");
    return { user: { id: user.id, email: user.email, name: user.name }, organization: org, workspace, ...this.issueToken(user.id, user.email, org.id, "OWNER"), ...session };
  }

  async login(raw: unknown, ip = "unknown") {
    const data = parseOrThrow(loginSchema, raw);
    const bucketKey = `${normalizeEmail(data.email)}|${ip}`;
    this.checkRateLimit(bucketKey);
    const user = await this.prisma.user.findUnique({ where: { email: data.email }, include: { memberships: { where: { status: "ACTIVE" }, take: 1 } } });
    const passwordOk = user ? await bcrypt.compare(data.password, user.passwordHash as string) : false;
    if (!user || !user.isActive || (user.status as string) === "DEACTIVATED" || (user.status as string) === "SUSPENDED" || !passwordOk) {
      this.recordAttempt(bucketKey);
      if (user) await this.event(user.id as string, null, "LOGIN_FAILED", ip);
      throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    }
    const membership = user.memberships[0];
    if (!membership) {
      this.recordAttempt(bucketKey);
      throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    }
    const organizationId = membership.organizationId as string;

    // SSO enforcement gate (§58/59) — checked only after the password has
    // been proven, so unauthenticated callers learn nothing.
    const gate = await this.ssoGate(organizationId, user.id as string);
    if (!gate.allowed) {
      await this.event(user.id as string, organizationId, "LOGIN_FAILED", ip);
      throw new ForbiddenException("Single sign-on is required for this organization");
    }

    // MFA gate (§24/25): org policy (all/admins) or an enrolled method.
    const mfa = await this.mfaGate(organizationId, user.id as string, membership.role as string);
    if (mfa.required) {
      const challengeToken = randomToken(32);
      await this.prisma.authChallenge.create({
        data: {
          userId: user.id, type: "MFA_TOTP", tokenHash: sha256Hex(challengeToken),
          expiresAt: new Date(Date.now() + 10 * 60_000),
          metadata: { organizationId, role: membership.role, enrolled: mfa.enrolled, breakGlass: gate.breakGlass },
        },
      });
      await this.event(user.id as string, organizationId, "MFA_CHALLENGE", ip);
      await this.audit.record({ actorId: user.id, organizationId, action: "MFA_CHALLENGE_ISSUED", resourceType: "User", resourceId: user.id });
      return { mfaRequired: true, enrolled: mfa.enrolled, challengeToken, user: { id: user.id, email: user.email, name: user.name } };
    }

    return this.completeLogin(user, membership, ip, gate.breakGlass, "AAL1");
  }

  /** Shared completion for password + (post-MFA) logins. Always mints a
   *  fresh server-side session — no pre-auth identifier is ever honored. */
  async completeLogin(user: Record<string, unknown>, membership: Record<string, unknown>, ip = "unknown", breakGlass = false, assurance = "AAL1") {
    const organizationId = membership.organizationId as string;
    await this.prisma.user.update({ where: { id: user.id as string }, data: { lastLoginAt: new Date() } });
    await this.event(user.id as string, organizationId, "LOGIN_SUCCESS", ip);
    await this.audit.record({ actorId: user.id as string, organizationId, action: "USER_LOGIN_SUCCEEDED", resourceType: "User", resourceId: user.id as string, ipAddress: ip === "unknown" ? undefined : ip });
    if (breakGlass) {
      await this.audit.record({ actorId: user.id as string, organizationId, action: "BREAK_GLASS_LOGIN", resourceType: "User", resourceId: user.id as string });
    }
    await this.audit.record({ actorId: user.id as string, organizationId, action: "LOGIN", resourceType: "User", resourceId: user.id as string });
    const session = await this.createSession(user.id as string, organizationId, assurance);
    return { user: { id: user.id, email: user.email, name: user.name }, ...this.issueToken(user.id as string, user.email as string, organizationId, membership.role as string), ...session };
  }

  private async createSession(userId: string, organizationId: string, assurance: string) {
    const token = randomToken(32);
    const now = Date.now();
    const session = await this.prisma.userSession.create({
      data: {
        userId, organizationId, tokenHash: sha256Hex(token), assurance: assurance as never,
        expiresAt: new Date(now + 720 * 60_000), idleExpiresAt: new Date(now + 30 * 60_000),
      },
    });
    return { sessionToken: token, sessionId: session.id as string };
  }

  private async mfaGate(organizationId: string, userId: string, role: string): Promise<{ required: boolean; enrolled: boolean }> {
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId } });
    const requirement = (policy?.mfaRequirement as string) ?? "OPTIONAL";
    const [totpCount, passkeyCount, recoveryCount] = await Promise.all([
      this.prisma.mfaMethod.count({ where: { userId, type: "TOTP", isActive: true } }),
      this.prisma.webAuthnCredential.count({ where: { userId } }),
      this.prisma.recoveryCode.count({ where: { userId, usedAt: null } }),
    ]);
    const enrolled = totpCount > 0 || passkeyCount > 0 || recoveryCount > 0;
    if (requirement === "REQUIRED_FOR_ALL") return { required: true, enrolled };
    if (requirement === "REQUIRED_FOR_ADMINS" && isPrivilegedOrgRole(role)) return { required: true, enrolled };
    return { required: enrolled, enrolled };
  }

  private async ssoGate(organizationId: string, userId: string): Promise<{ allowed: boolean; breakGlass: boolean }> {
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId } });
    const providers = await this.prisma.enterpriseSsoProvider.findMany({ where: { organizationId, enabled: true } });
    const enforced = (policy?.ssoRequirement as string) === "SSO_REQUIRED" || providers.some((p) => p.enforceSso);
    if (!enforced) return { allowed: true, breakGlass: false };
    const enrollment = await this.prisma.breakGlassEnrollment.findFirst({ where: { organizationId, userId, status: "ACTIVE" } });
    if (!enrollment) return { allowed: false, breakGlass: false };
    await this.prisma.breakGlassEnrollment.update({ where: { id: enrollment.id }, data: { lastUsedAt: new Date() } });
    await this.event(userId, organizationId, "BREAK_GLASS_LOGIN", "unknown");
    return { allowed: true, breakGlass: true };
  }

  private checkRateLimit(key: string) {
    const decision = rateLimitDecision(this.attempts, key, Date.now(), 10, 15 * 60_000);
    if (!decision.allowed) {
      throw new HttpException(GENERIC_AUTH_ERROR, HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  private recordAttempt(key: string) {
    const now = Date.now();
    const bucket = this.attempts.find((b) => b.key === key && now - b.windowStartMs < 15 * 60_000);
    if (bucket) bucket.count += 1;
    else this.attempts.push({ key, count: 1, windowStartMs: now });
  }

  private async event(userId: string | null, organizationId: string | null, eventType: string, ip: string) {
    await this.prisma.authenticationEvent.create({
      data: { userId, organizationId, eventType, ipAddress: ip === "unknown" ? null : ip },
    });
  }

  private issueToken(sub: string, email: string, organizationId: string, role: string) {
    return { accessToken: this.jwt.sign({ sub, email, organizationId, role }) };
  }
}
