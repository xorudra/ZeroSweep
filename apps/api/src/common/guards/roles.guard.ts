import { ForbiddenException, Injectable, type CanActivate, type ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ROLES_KEY, type RequestUser } from "../decorators/auth.decorators";
import type { Role } from "@dsrclone/types";

/** RBAC is enforced on the backend — frontend checks are never trusted. */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}
  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [context.getHandler(), context.getClass()]);
    if (!required || required.length === 0) return true;
    const req = context.switchToHttp().getRequest<{ user?: RequestUser }>();
    if (!req.user || !required.includes(req.user.role)) {
      throw new ForbiddenException("Insufficient role for this action");
    }
    return true;
  }
}
