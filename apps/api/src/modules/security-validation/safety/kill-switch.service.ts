import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { KILL_SWITCH_LEVELS } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";

/**
 * Validation kill switches (Prompt 16 §43). Activation is an emergency
 * action: it blocks new validations at the matching level immediately
 * and the worker terminates active sessions (§89). Every activation
 * and clearing is audited (§80: KILL_SWITCH_ACTIVATED).
 */
@Injectable()
export class KillSwitchService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async list(user: RequestUser, workspaceId: string) {
    return this.prisma.validationKillSwitch.findMany({
      where: {
        OR: [
          { level: "GLOBAL" },
          { organizationId: user.organizationId },
          { workspaceId },
        ],
      },
      orderBy: { activatedAt: "desc" },
      take: 100,
    });
  }

  async activate(user: RequestUser, workspaceId: string, input: { level: string; scopeRef?: string; reason?: string }) {
    requireValidationPermission(user, "MANAGE_VALIDATION_POLICY");
    if (!(KILL_SWITCH_LEVELS as readonly string[]).includes(input.level)) {
      throw new BadRequestException(`level must be one of ${KILL_SWITCH_LEVELS.join(", ")} (§43)`);
    }
    if (["SCAN", "TARGET", "SESSION"].includes(input.level) && !input.scopeRef) {
      throw new BadRequestException(`level ${input.level} requires a scopeRef (§43)`);
    }
    const row = await this.prisma.validationKillSwitch.create({
      data: {
        level: input.level,
        organizationId: input.level === "ORGANIZATION" || input.level === "GLOBAL" ? user.organizationId : undefined,
        workspaceId: input.level === "GLOBAL" ? undefined : workspaceId,
        scopeRef: input.scopeRef,
        reason: input.reason,
        activatedBy: user.id,
        active: true,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "KILL_SWITCH_ACTIVATED", resourceType: "ValidationKillSwitch", resourceId: row.id,
      metadata: { level: input.level, scopeRef: input.scopeRef ?? null, reason: input.reason ?? null },
    });
    return row;
  }

  async clear(user: RequestUser, workspaceId: string, id: string) {
    requireValidationPermission(user, "MANAGE_VALIDATION_POLICY");
    const row = await this.prisma.validationKillSwitch.findFirst({
      where: { id, OR: [{ workspaceId }, { organizationId: user.organizationId }, { level: "GLOBAL" }] },
    });
    if (!row) throw new NotFoundException("kill switch not found");
    const updated = await this.prisma.validationKillSwitch.update({
      where: { id },
      data: { active: false, clearedBy: user.id, clearedAt: new Date() },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "KILL_SWITCH_ACTIVATED", resourceType: "ValidationKillSwitch", resourceId: id,
      metadata: { cleared: true, level: row.level },
    });
    return updated;
  }
}
