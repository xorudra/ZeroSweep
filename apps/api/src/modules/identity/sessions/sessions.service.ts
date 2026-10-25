import { Inject, Injectable, NotFoundException, UnauthorizedException } from "@nestjs/common";
import {
  clampSessionPolicy, randomToken, sessionExpired, sha256Hex, type AssuranceLevel,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";

export interface SessionContext {
  id: string;
  email: string;
  organizationId: string;
  role: string;
}

/**
 * Server-side sessions (§38–44): opaque random tokens, only SHA-256 hashes
 * stored (§39), idle + absolute expiry clamped to platform safety bounds
 * (§42), rotation on authentication events (§41 — a fresh session is always
 * minted; pre-auth identifiers never become privileged, §122), and
 * revocation enforced at validation time (§43/§123).
 */
@Injectable()
export class SessionsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async createSession(ctx: SessionContext & { workspaceId?: string; assurance?: AssuranceLevel; deviceSummary?: string }) {
    const policy = await this.policyFor(ctx.organizationId);
    const { idleMinutes, absoluteMinutes } = clampSessionPolicy(policy.idle, policy.absolute);
    const token = randomToken(32);
    const now = new Date();
    const session = await this.prisma.userSession.create({
      data: {
        userId: ctx.id, organizationId: ctx.organizationId, workspaceId: ctx.workspaceId ?? null,
        tokenHash: sha256Hex(token), assurance: ctx.assurance ?? "AAL1", deviceSummary: ctx.deviceSummary ?? null,
        expiresAt: new Date(now.getTime() + absoluteMinutes * 60_000),
        idleExpiresAt: new Date(now.getTime() + idleMinutes * 60_000),
      },
    });
    return { sessionToken: token, sessionId: session.id as string, expiresAt: session.expiresAt as Date };
  }

  /** Validate an opaque session token → request context, or a specific
   *  rejection reason. Touch updates lastSeenAt (idle window slides). */
  async validateSessionToken(token: string, nowMs = Date.now()) {
    const session = await this.prisma.userSession.findUnique({ where: { tokenHash: sha256Hex(token) } });
    if (!session) throw new UnauthorizedException("Invalid session");
    const policy = await this.policyFor(session.organizationId as string);
    const { idleMinutes, absoluteMinutes } = clampSessionPolicy(policy.idle, policy.absolute);
    const expired = sessionExpired({
      createdAtMs: new Date(session.createdAt as Date).getTime(),
      lastSeenAtMs: new Date(session.lastSeenAt as Date).getTime(),
      idleMinutes, absoluteMinutes,
      revokedAtMs: session.revokedAt ? new Date(session.revokedAt as Date).getTime() : null,
    }, nowMs);
    if (expired) throw new UnauthorizedException(`Session ${expired.toLowerCase().replace("_", " ")}`);
    const user = await this.prisma.user.findUnique({ where: { id: session.userId } });
    if (!user || !(user.isActive as boolean) || (user.status as string) === "DEACTIVATED" || (user.status as string) === "SUSPENDED") {
      throw new UnauthorizedException("Account is not active");
    }
    const membership = await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId: session.organizationId, status: "ACTIVE" } });
    if (!membership) throw new UnauthorizedException("Membership is not active");
    // Privilege changes take effect immediately (§124): role comes from the
    // CURRENT membership row, never from a stale token claim.
    await this.prisma.userSession.update({ where: { id: session.id }, data: { lastSeenAt: new Date(nowMs) } });
    return {
      sessionId: session.id as string,
      user: { id: user.id as string, email: user.email as string, organizationId: session.organizationId as string, role: membership.role as SessionContext["role"] },
      assurance: session.assurance as string,
      stepUpAt: session.stepUpAt ? new Date(session.stepUpAt as Date).getTime() : null,
    };
  }

  /** Launch Safety A7 — refresh rotation: replace the session's
   *  credential in place. The session row (and its id, hence the `sid`
   *  claim of JWTs minted for it) survives; the previously presented
   *  token dies immediately because only the new token's hash is stored.
   *  Callers must validate the presented token first (validateSessionToken).
   *
   *  The write is an atomic compare-and-swap on the PRESENTED token's
   *  hash: of two concurrent refreshes presenting the same credential,
   *  exactly one wins. A CAS miss means the credential was already
   *  rotated (replay of a superseded credential, or the loser of the
   *  race) — treated as token reuse: the whole session family is
   *  revoked, so neither the replayed nor the winning credential can
   *  be used again, and the reuse is recorded as an auth event. */
  async rotateSessionCredential(sessionId: string, presentedToken: string) {
    const token = randomToken(32);
    const result = await this.prisma.userSession.updateMany({
      where: { id: sessionId, tokenHash: sha256Hex(presentedToken), revokedAt: null },
      data: { tokenHash: sha256Hex(token), lastSeenAt: new Date() },
    });
    if (result.count === 0) {
      const session = await this.prisma.userSession.findUnique({ where: { id: sessionId } });
      await this.prisma.userSession.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date() } });
      if (session) {
        await this.prisma.authenticationEvent.create({ data: { userId: session.userId, organizationId: session.organizationId, eventType: "SESSION_TOKEN_REUSE_DETECTED" } });
      }
      throw new UnauthorizedException("Session credential reuse detected");
    }
    return { sessionToken: token };
  }

  async listSessions(userId: string, currentSessionId?: string) {
    const rows = await this.prisma.userSession.findMany({ where: { userId }, orderBy: { createdAt: "desc" }, take: 50 });
    return rows.map((s) => ({
      id: s.id, deviceSummary: s.deviceSummary, createdAt: s.createdAt, lastSeenAt: s.lastSeenAt,
      expiresAt: s.expiresAt, revokedAt: s.revokedAt, assurance: s.assurance,
      current: currentSessionId ? s.id === currentSessionId : false,
    }));
  }

  async revokeSession(actor: SessionContext, sessionId: string) {
    const session = await this.prisma.userSession.findUnique({ where: { id: sessionId } });
    if (!session || (session.userId !== actor.id && !["OWNER", "ADMIN", "SECURITY_ADMIN"].includes(actor.role))) {
      throw new NotFoundException("Session not found");
    }
    if ((session.organizationId as string) !== actor.organizationId && session.userId !== actor.id) throw new NotFoundException("Session not found");
    await this.prisma.userSession.update({ where: { id: sessionId }, data: { revokedAt: new Date() } });
    await this.prisma.authenticationEvent.create({ data: { userId: session.userId, organizationId: session.organizationId, eventType: "SESSION_REVOKED" } });
    await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "SESSION_REVOKED", resourceType: "UserSession", resourceId: sessionId });
    return { revoked: true };
  }

  async revokeAllSessions(actor: SessionContext, userId: string) {
    if (userId !== actor.id && !["OWNER", "ADMIN", "SECURITY_ADMIN"].includes(actor.role)) throw new NotFoundException("User not found");
    const result = await this.prisma.userSession.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
    await this.audit.record({ actorId: actor.id, organizationId: actor.organizationId, action: "SESSIONS_REVOKED_ALL", resourceType: "User", resourceId: userId, metadata: { count: result.count } });
    return { revokedCount: result.count };
  }

  async markStepUp(sessionId: string) {
    await this.prisma.userSession.update({ where: { id: sessionId }, data: { stepUpAt: new Date() } });
  }

  private async policyFor(organizationId: string): Promise<{ idle: number; absolute: number }> {
    const policy = await this.prisma.organizationSecurityPolicy.findUnique({ where: { organizationId } });
    return { idle: (policy?.sessionIdleMinutes as number) ?? 30, absolute: (policy?.sessionAbsoluteMinutes as number) ?? 720 };
  }
}
