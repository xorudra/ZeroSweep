import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { loadEnv } from "@zerosweep/config";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { assertSessionLive } from "../../common/session-liveness";
import type { RequestUser } from "../../common/decorators/auth.decorators";

interface JwtPayload { sub: string; email: string; name?: string; organizationId: string; role: RequestUser["role"]; isPlatformAdmin?: boolean; sid?: string; }

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: loadEnv().JWT_SECRET,
    });
  }
  async validate(payload: JwtPayload): Promise<RequestUser> {
    if (!payload?.sub || !payload?.organizationId) throw new UnauthorizedException();
    // Launch Safety A7: signature + expiry are necessary but no longer
    // sufficient. Every platform JWT is bound to the server-side session
    // it was minted for (`sid`); that session must still be live under
    // the same rules the opaque session token is held to (see
    // common/session-liveness). A missing/unknown/revoked/expired
    // session is a 401 — so logout, password reset/change and admin
    // revocation cut API access immediately, not at JWT expiry.
    if (!payload.sid) throw new UnauthorizedException();
    await assertSessionLive(this.prisma, payload.sid, payload.sub);
    // §124 (security audit 2026-10-16, stale-jwt-role-after-demotion):
    // authorization facts are re-derived per request from CURRENT state,
    // exactly as SessionsService.validateSessionToken does — a demoted
    // member's live JWT immediately authorizes at the new role (or 401s
    // when the membership/user is no longer active), never at the role
    // baked into the token at issuance.
    const user = await this.prisma.user.findUnique({ where: { id: payload.sub } });
    if (!user || !(user.isActive as boolean) || ["SUSPENDED", "DEACTIVATED"].includes(user.status as string)) throw new UnauthorizedException();
    const membership = await this.prisma.membership.findFirst({ where: { userId: payload.sub, organizationId: payload.organizationId, status: "ACTIVE" } });
    if (!membership) throw new UnauthorizedException();
    return { id: payload.sub, email: payload.email, name: payload.name, organizationId: payload.organizationId, role: membership.role as RequestUser["role"], isPlatformAdmin: (user.isPlatformAdmin as boolean) === true, sessionId: payload.sid };
  }
}
