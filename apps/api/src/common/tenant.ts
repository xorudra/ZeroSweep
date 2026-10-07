import { ForbiddenException, NotFoundException } from "@nestjs/common";
import type { PrismaClientLike } from "../prisma/prisma.module";
import type { RequestUser } from "./decorators/auth.decorators";

/**
 * Tenant resolution: every workspace-bound query must pass through here so a
 * user can only ever touch workspaces/targets inside their own organization.
 */
export async function resolveWorkspace(prisma: PrismaClientLike, user: RequestUser, workspaceId?: string) {
  const workspace = workspaceId
    ? await prisma.workspace.findFirst({ where: { id: workspaceId, organizationId: user.organizationId, deletedAt: null } })
    : await prisma.workspace.findFirst({ where: { organizationId: user.organizationId, deletedAt: null }, orderBy: { createdAt: "asc" } });
  if (!workspace) throw workspaceId ? new ForbiddenException("Workspace is outside your organization") : new NotFoundException("No workspace found for your organization");
  return workspace;
}

export async function assertTargetInOrg(prisma: PrismaClientLike, user: RequestUser, targetId: string) {
  const target = await prisma.target.findFirst({
    where: { id: targetId, deletedAt: null, workspace: { organizationId: user.organizationId } },
  });
  if (!target) throw new NotFoundException("Target not found");
  return target;
}
