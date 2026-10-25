import { BadRequestException, Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import * as bcrypt from "bcryptjs";
import {
  GENERIC_AUTH_ERROR, GENERIC_RESET_MESSAGE, randomToken, sha256Hex,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import { AuthService } from "../auth/auth.service";
import { MfaService } from "./mfa/mfa.service";
import { SessionsService } from "./sessions/sessions.service";
import { GovernanceService } from "./governance/governance.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Authentication completion flows (§101, §110–112): MFA challenge
 * verification (completes a gated login), challenge-bound TOTP enrollment
 * for users locked into MFA by policy, password reset (hashed, single-use,
 * short-lived, session-revoking) and password change.
 */
@Injectable()
export class AuthFlowService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly auth: AuthService,
    private readonly mfa: MfaService,
    private readonly sessions: SessionsService,
    private readonly governance: GovernanceService,
  ) {}

  /** Enroll TOTP against a login challenge (policy-required MFA with no
   *  method yet). The secret is shown once; activation happens in verify.
   *  NEVER for an already-enrolled account (security audit 2026-10-16
   *  run-5, high): a challenge must not let its holder substitute a new
   *  factor for the enrolled one — that would reduce MFA to the password
   *  alone. The login records `enrolled` in the challenge metadata; the
   *  live method check backs it up. Factor replacement belongs to the
   *  authenticated step-up / admin-reset paths. */
  async enrollViaChallenge(challengeToken: string) {
    const challenge = await this.loadChallenge(challengeToken);
    const user = await this.prisma.user.findUnique({ where: { id: challenge.userId } });
    if (!user) throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    const meta = challenge.metadata as { organizationId: string; role: string; enrolled?: boolean };
    if (meta.enrolled === true) throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    const activeMethod = await this.prisma.mfaMethod.findFirst({ where: { userId: user.id, isActive: true } });
    if (activeMethod) throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    const synthetic: RequestUser = { id: user.id as string, email: user.email as string, organizationId: meta.organizationId, role: meta.role as RequestUser["role"] };
    return this.mfa.enrollTotp(synthetic);
  }

  /** Verify an MFA challenge with a TOTP or recovery code and complete the
   *  login (§101). Failed attempts are bounded; success consumes the
   *  challenge and mints a fresh AAL2 session. */
  async verifyMfaChallenge(challengeToken: string, body: { code?: string; recoveryCode?: string }) {
    const challenge = await this.loadChallenge(challengeToken);
    // Atomic budget claim (security audit 2026-10-16 run-4): one of the
    // login's 5 guess slots is claimed BEFORE any code is tested, via a
    // conditional updateMany CAS — concurrent verifies can no longer
    // each test a code against a stale snapshot and multiply the bound.
    // A count of 0 means the budget is exhausted (or the challenge was
    // consumed concurrently); the outward error is generic either way.
    const claim = await this.prisma.authChallenge.updateMany({
      where: { id: challenge.id, consumedAt: null, attempts: { lt: 5 } },
      data: { attempts: { increment: 1 } },
    });
    if (claim.count === 0) throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    const meta = challenge.metadata as { organizationId: string; role: string; breakGlass?: boolean; enrolled?: boolean };
    const userId = challenge.userId as string;
    let ok = false;
    if (body.code) {
      // First-code activation for a just-enrolled pending method — ONLY
      // on an unenrolled challenge (run-5 high): on an enrolled account
      // a pending method must never preempt the enrolled factor.
      const activeTotp = await this.prisma.mfaMethod.findFirst({ where: { userId, type: "TOTP", isActive: true } });
      const unenrolled = meta.enrolled !== true && !activeTotp;
      const pending = unenrolled ? await this.prisma.mfaMethod.findFirst({ where: { userId, type: "TOTP", isActive: false } }) : null;
      if (pending) {
        const user = await this.prisma.user.findUnique({ where: { id: userId } });
        const synthetic: RequestUser = { id: userId, email: user?.email as string, organizationId: meta.organizationId, role: meta.role as RequestUser["role"] };
        try { await this.mfa.activateTotp(synthetic, body.code); ok = true; } catch { ok = false; }
      } else {
        ok = await this.mfa.verifyTotpForUser(userId, meta.organizationId, body.code);
      }
    } else if (body.recoveryCode) {
      ok = await this.mfa.consumeRecoveryCode(userId, meta.organizationId, body.recoveryCode);
    }
    if (!ok) {
      // The claimed slot stays consumed — that IS the failure accounting.
      throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    }
    // Success consumes the challenge atomically: a racing duplicate
    // verify finds it already consumed and mints no second session.
    const consumed = await this.prisma.authChallenge.updateMany({
      where: { id: challenge.id, consumedAt: null },
      data: { consumedAt: new Date() },
    });
    if (consumed.count === 0) throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    const membership = await this.prisma.membership.findFirst({ where: { userId, organizationId: meta.organizationId, status: "ACTIVE" } });
    if (!user || !membership) throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    return this.auth.completeLogin(user, membership, "unknown", Boolean(meta.breakGlass), "AAL2");
  }

  /** Password reset request (§110): the outward response is ALWAYS the
   *  generic message (no enumeration, §109). A hashed, single-use,
   *  30-minute token is created when the account exists; delivery happens
   *  through the notification channel (recorded-not-delivered until an
   *  email provider is configured — Prompt 22 semantics). */
  async requestPasswordReset(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    let resetToken: string | undefined;
    if (user && (user.isActive as boolean)) {
      resetToken = randomToken(32);
      await this.prisma.authChallenge.create({
        data: { userId: user.id, type: "PASSWORD_RESET", tokenHash: sha256Hex(resetToken), expiresAt: new Date(Date.now() + 30 * 60_000) },
      });
      await this.audit.record({ actorId: user.id as string, action: "PASSWORD_RESET_REQUESTED", resourceType: "User", resourceId: user.id as string });
    }
    return { message: GENERIC_RESET_MESSAGE, resetToken };
  }

  async resetPassword(token: string, newPassword: string) {
    const challenge = await this.prisma.authChallenge.findUnique({ where: { tokenHash: sha256Hex(token) } });
    if (!challenge || challenge.type !== "PASSWORD_RESET" || challenge.consumedAt || new Date(challenge.expiresAt as Date).getTime() < Date.now()) {
      throw new BadRequestException("Reset token is invalid or expired");
    }
    const user = await this.prisma.user.findUnique({ where: { id: challenge.userId } });
    if (!user) throw new BadRequestException("Reset token is invalid or expired");
    const membership = await this.prisma.membership.findFirst({ where: { userId: user.id, status: "ACTIVE" } });
    if (membership) await this.governance.assertPasswordAllowed(membership.organizationId as string, newPassword);
    await this.prisma.user.update({ where: { id: user.id }, data: { passwordHash: await bcrypt.hash(newPassword, 12) } });
    await this.prisma.authChallenge.update({ where: { id: challenge.id }, data: { consumedAt: new Date() } });
    // §110: a successful reset revokes the account's sessions.
    await this.prisma.userSession.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } });
    await this.audit.record({ actorId: user.id as string, organizationId: membership?.organizationId as string, action: "PASSWORD_RESET_COMPLETED", resourceType: "User", resourceId: user.id as string });
    await this.prisma.authenticationEvent.create({ data: { userId: user.id, eventType: "PASSWORD_CHANGED" } });
    return { reset: true };
  }

  /** Password change (§111): requires the current password; revokes other
   *  sessions; audited + notified via authentication events (§113). */
  async changePassword(user: RequestUser, body: { currentPassword: string; newPassword: string; currentSessionId?: string }) {
    const record = await this.prisma.user.findUnique({ where: { id: user.id } });
    if (!record || !(await bcrypt.compare(body.currentPassword, record.passwordHash as string))) {
      throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    }
    await this.governance.assertPasswordAllowed(user.organizationId, body.newPassword);
    await this.prisma.user.update({ where: { id: user.id }, data: { passwordHash: await bcrypt.hash(body.newPassword, 12) } });
    const sessions = await this.prisma.userSession.findMany({ where: { userId: user.id, revokedAt: null } });
    for (const s of sessions) {
      if (body.currentSessionId && s.id === body.currentSessionId) continue;
      await this.prisma.userSession.update({ where: { id: s.id }, data: { revokedAt: new Date() } });
    }
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "PASSWORD_CHANGED", resourceType: "User", resourceId: user.id });
    await this.prisma.authenticationEvent.create({ data: { userId: user.id, organizationId: user.organizationId, eventType: "PASSWORD_CHANGED" } });
    return { changed: true };
  }

  /** Step-up (§35): re-prove with TOTP, then the session is marked fresh. */
  async stepUp(user: RequestUser, body: { sessionId: string; code: string }) {
    const ok = await this.mfa.verifyTotpForUser(user.id, user.organizationId, body.code);
    if (!ok) {
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "STEP_UP_REQUIRED", resourceType: "UserSession", resourceId: body.sessionId });
      throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    }
    await this.sessions.markStepUp(body.sessionId);
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, action: "STEP_UP_SUCCEEDED", resourceType: "UserSession", resourceId: body.sessionId });
    return { steppedUp: true };
  }

  private async loadChallenge(challengeToken: string) {
    const challenge = await this.prisma.authChallenge.findUnique({ where: { tokenHash: sha256Hex(challengeToken) } });
    if (!challenge || challenge.type !== "MFA_TOTP" || challenge.consumedAt || new Date(challenge.expiresAt as Date).getTime() < Date.now()) {
      throw new UnauthorizedException(GENERIC_AUTH_ERROR);
    }
    return challenge;
  }
}
