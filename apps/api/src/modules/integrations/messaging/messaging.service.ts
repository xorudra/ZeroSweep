import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { EventsService } from "../events/events.service";
import { CicdService } from "../cicd/cicd.service";

type Row = Record<string, unknown>;

/**
 * Messaging fan-out (Prompt 24 §55–§59). This service does NOT send
 * chat messages itself and does not duplicate notification logic
 * (§59): it publishes a canonical event whose deliveries are queued
 * for the workspace's SLACK / MICROSOFT_TEAMS integrations, and the
 * outbox processor performs delivery through the connectors. Alert
 * payloads are built from sanitized finding views (§56).
 */
@Injectable()
export class MessagingService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly events: EventsService,
    private readonly cicd: CicdService,
  ) {}

  async sendFindingAlert(user: RequestUser, workspaceId: string, findingId: string) {
    requireIntegrationPermission(user, "MANAGE_MESSAGING_INTEGRATIONS");
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) return { queued: 0, detail: "finding not found" };
    const integrations = await this.prisma.integration.findMany({
      where: { workspaceId, enabled: true, type: { in: ["SLACK", "MICROSOFT_TEAMS"] } },
    }) as Row[];
    if (integrations.length === 0) {
      return { queued: 0, detail: "no Slack/Teams integration is configured in this workspace — nothing was sent" };
    }
    const view = this.cicd.toSanitizedView(finding as Row);
    const { deliveries } = await this.events.publish({
      workspaceId,
      eventType: "finding.created",
      resourceType: "Finding",
      resourceId: findingId,
      payload: { finding: view as unknown as Record<string, unknown> },
      extraDeliveries: integrations.map((i) => ({
        destinationKind: i.type === "SLACK" ? "SLACK" : "TEAMS",
        integrationId: i.id as string,
      })),
    });
    return { queued: deliveries, detail: "alert queued for delivery via the integration outbox (§59)" };
  }
}
