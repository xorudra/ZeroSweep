import { ForbiddenException, type ExecutionContext } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { RolesGuard } from "./roles.guard";

function ctxWithRole(role?: string): ExecutionContext {
  return {
    getHandler: () => ({}),
    getClass: () => ({}),
    switchToHttp: () => ({ getRequest: () => ({ user: role ? { id: "u1", email: "a@b.c", organizationId: "o1", role } : undefined }) }),
  } as unknown as ExecutionContext;
}

describe("RolesGuard (RBAC)", () => {
  it("allows when no roles are required", () => {
    const guard = new RolesGuard(new Reflector());
    expect(guard.canActivate(ctxWithRole("VIEWER"))).toBe(true);
  });
  it("allows a user with a required role and denies others", () => {
    const reflector = { getAllAndOverride: () => ["OWNER", "ADMIN"] } as unknown as Reflector;
    const guard = new RolesGuard(reflector);
    expect(guard.canActivate(ctxWithRole("ADMIN"))).toBe(true);
    expect(() => guard.canActivate(ctxWithRole("VIEWER"))).toThrow(ForbiddenException);
    expect(() => guard.canActivate(ctxWithRole(undefined))).toThrow(ForbiddenException);
  });
});
