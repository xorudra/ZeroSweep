import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { loadEnv } from "@dsrclone/config";
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
    return { id: payload.sub, email: payload.email, name: payload.name, organizationId: payload.organizationId, role: payload.role, isPlatformAdmin: payload.isPlatformAdmin === true, sessionId: payload.sid };
  }
}
