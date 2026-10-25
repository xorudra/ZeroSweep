import { UnauthorizedException } from "@nestjs/common";
import { clampSessionPolicy, sessionExpired } from "@zerosweep/security-sdk";
import type { PrismaClientLike } from "../prisma/prisma.module";

/**
 * Launch Safety A7 — session liveness for session-linked JWTs.
 *
 * A platform JWT now carries the id (`sid`) of the server-side UserSession
 * it was minted for, and the JWT guard re-checks that session on every
 * request. The rules are EXACTLY the ones SessionsService applies to the
 * opaque session token (§42/§43): the organization's session policy
 * clamped to platform safety bounds, revoked / absolute / idle evaluated
 * by the shared `sessionExpired` helper, and a successful check touches
 * `lastSeenAt` so the idle window slides with activity. The duplication of
 * the policy lookup is deliberate: the auth module cannot import the
 * identity module (which owns SessionsService) without a cycle, and both
 * sides share the security-sdk primitives that define the rules.
 */
export async function sessionPolicyFor(
  prisma: PrismaClientLike,
  organizationId: string,
): Promise<{ idleMinutes: number; absoluteMinutes: number }> {
  const policy = await prisma.organizationSecurityPolicy.findUnique({ where: { organizationId } });
  return clampSessionPolicy(
    (policy?.sessionIdleMinutes as number) ?? 30,
    (policy?.sessionAbsoluteMinutes as number) ?? 720,
  );
}

/** Throws UnauthorizedException unless the named session exists, belongs
 *  to the named user, and is neither revoked nor past its absolute/idle
 *  windows. On success the session's idle window slides (lastSeenAt). */
export async function assertSessionLive(
  prisma: PrismaClientLike,
  sessionId: string,
  userId: string,
  nowMs: number = Date.now(),
): Promise<void> {
  const session = await prisma.userSession.findUnique({ where: { id: sessionId } });
  if (!session || (session.userId as string) !== userId) {
    throw new UnauthorizedException("Session is not active");
  }
  const { idleMinutes, absoluteMinutes } = await sessionPolicyFor(prisma, session.organizationId as string);
  const expired = sessionExpired({
    createdAtMs: new Date(session.createdAt as Date).getTime(),
    lastSeenAtMs: new Date(session.lastSeenAt as Date).getTime(),
    idleMinutes,
    absoluteMinutes,
    revokedAtMs: session.revokedAt ? new Date(session.revokedAt as Date).getTime() : null,
  }, nowMs);
  if (expired) throw new UnauthorizedException(`Session ${expired.toLowerCase().replace("_", " ")}`);
  await prisma.userSession.update({ where: { id: sessionId }, data: { lastSeenAt: new Date(nowMs) } });
}
