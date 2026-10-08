import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { loadEnv } from "@dsrclone/config";
import type { RequestUser } from "../../common/decorators/auth.decorators";

interface JwtPayload { sub: string; email: string; organizationId: string; role: RequestUser["role"]; isPlatformAdmin?: boolean; }

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: loadEnv().JWT_SECRET,
    });
  }
  async validate(payload: JwtPayload): Promise<RequestUser> {
    if (!payload?.sub || !payload?.organizationId) throw new UnauthorizedException();
    return { id: payload.sub, email: payload.email, organizationId: payload.organizationId, role: payload.role, isPlatformAdmin: payload.isPlatformAdmin === true };
  }
}
