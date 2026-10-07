import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";

export interface AuditEntry {
  actorId?: string;
  organizationId?: string;
  workspaceId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
  ipAddress?: string;
}

/** Audit logging. Metadata must never contain passwords, tokens or secrets —
 *  callers pass identifiers only; the logger redacts as a second line of defence. */
@Injectable()
export class AuditService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async record(entry: AuditEntry): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        actorId: entry.actorId, organizationId: entry.organizationId, workspaceId: entry.workspaceId,
        action: entry.action as never, resourceType: entry.resourceType, resourceId: entry.resourceId,
        metadata: entry.metadata as never, ipAddress: entry.ipAddress,
      },
    });
  }

  async list(organizationId: string, page: number, pageSize: number) {
    const [items, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where: { organizationId }, orderBy: { createdAt: "desc" },
        skip: (page - 1) * pageSize, take: pageSize,
      }),
      this.prisma.auditLog.count({ where: { organizationId } }),
    ]);
    return { items, total, page, pageSize };
  }
}
