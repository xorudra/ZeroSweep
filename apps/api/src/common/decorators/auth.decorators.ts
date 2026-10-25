import { createParamDecorator, SetMetadata, type ExecutionContext } from "@nestjs/common";
import type { Role } from "@zerosweep/types";

export const ROLES_KEY = "zerosweep:roles";
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
export const IS_PUBLIC_KEY = "zerosweep:public";
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

export interface RequestUser {
  id: string;
  email: string;
  name?: string;
  organizationId: string;
  role: Role;
  /** Deployment-level platform administrator (Prompt 40 §96). Carried in
   *  the token from the user row, which login reconciles against the
   *  trusted deployment allowlist — never from request input. */
  isPlatformAdmin?: boolean;
  /** Launch Safety A7: id of the server-side UserSession this request's
   *  JWT was minted for (the token's `sid` claim). The JWT guard verifies
   *  the session is still live on every request, so this always names a
   *  real, unrevoked session for authenticated requests. */
  sessionId?: string;
}

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext): RequestUser => {
  const req = ctx.switchToHttp().getRequest<{ user: RequestUser }>();
  return req.user;
});
