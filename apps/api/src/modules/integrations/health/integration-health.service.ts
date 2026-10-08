import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { IntegrationsService } from "../core/integrations.service";

type Row = Record<string, unknown>;

/**
 * Integration health overview (Prompt 24 §95–§100, §104): per
 * integration authentication state, reachability, rate-limit posture,
 * webhook state, last success and last error CATEGORY (never raw
 * provider error bodies, which can carry secrets). A provider outage
 * degrades the INTEGRATION only — core platform functions are never
 * blocked by an integration's health (§104).
 */
@Injectable()
export class IntegrationHealthService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly integrations: IntegrationsService,
  ) {}

  async overview(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const rows = await this.prisma.integration.findMany({ where: { workspaceId } }) as Row[];
    const checkpoints = await this.prisma.integrationSyncCheckpoint.findMany({ where: { workspaceId } }) as Row[];
    const recentDeliveries = await this.prisma.integrationDelivery.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
      take: 200,
    }) as Row[];
    return rows.map((row) => {
      const checkpoint = checkpoints
        .filter((c) => c.integrationId === row.id)
        .sort((a, b) => new Date(b.updatedAt as string).getTime() - new Date(a.updatedAt as string).getTime())[0];
      const deliveries = recentDeliveries.filter((d) => d.integrationId === row.id);
      const lastDelivery = deliveries[0];
      const deadLetters = deliveries.filter((d) => d.status === "DEAD_LETTER").length;
      return {
        integrationId: row.id,
        name: row.name,
        type: row.type,
        status: row.status ?? "PENDING",
        lastHealthCheckAt: row.lastHealthCheckAt ?? null,
        lastSyncAt: row.lastSyncAt ?? null,
        lastErrorCategory: row.lastErrorCategory ?? null,
        healthDetail: row.healthDetail ?? null,
        syncCheckpoint: checkpoint
          ? { resourceKind: checkpoint.resourceKind, lastSuccessAt: checkpoint.lastSuccessAt ?? null, lastErrorCategory: checkpoint.lastErrorCategory ?? null }
          : null,
        deliveryHealth: {
          recent: deliveries.length,
          deadLetters,
          lastStatus: lastDelivery?.status ?? null,
        },
        corePlatformAffected: false, // §104: integration health never gates the platform
      };
    });
  }

  /** Re-probe one integration and persist the outcome (§95). */
  async probe(user: RequestUser, workspaceId: string, id: string) {
    return this.integrations.test(user, workspaceId, id);
  }
}
