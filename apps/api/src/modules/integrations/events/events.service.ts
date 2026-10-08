import { Inject, Injectable } from "@nestjs/common";
import {
  WEBHOOK_EVENT_TYPES,
  createEventEnvelope,
  type SecurityEventEnvelope,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";

type Row = Record<string, unknown>;

/**
 * SecurityEventBus (Prompt 24 §75–§80). Modules publish canonical
 * events here; integrations NEVER get called by scanners directly.
 * The business-facing publish writes the outbox row and the delivery
 * rows together (§78: with a live database this runs inside the same
 * transaction as the caller's change — the processor contract is
 * at-least-once delivery + idempotent consumers, §131).
 */
@Injectable()
export class EventsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async publish(input: {
    workspaceId: string;
    eventType: string;
    resourceType: string;
    resourceId: string;
    payload: Record<string, unknown>;
    /** Extra one-off deliveries (messaging/SIEM fan-out decisions made
     *  by the calling service). */
    extraDeliveries?: Array<{ destinationKind: string; integrationId?: string; subscriptionId?: string }>;
  }): Promise<{ envelope: SecurityEventEnvelope; deliveries: number }> {
    const envelope = createEventEnvelope({
      eventType: input.eventType,
      workspaceId: input.workspaceId,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      payload: input.payload,
    });
    const outbox = await this.prisma.securityEventOutbox.create({
      data: {
        workspaceId: input.workspaceId,
        eventId: envelope.eventId,
        eventType: envelope.eventType,
        resourceType: envelope.resourceType,
        resourceId: envelope.resourceId,
        schemaVersion: envelope.schemaVersion,
        payload: envelope as never,
        status: "PENDING",
      },
    });

    let deliveries = 0;
    // §69/§73: generic webhook subscriptions subscribed to this event.
    if ((WEBHOOK_EVENT_TYPES as readonly string[]).includes(input.eventType)) {
      const subscriptions = await this.prisma.webhookSubscription.findMany({
        where: { workspaceId: input.workspaceId, enabled: true },
      });
      for (const sub of subscriptions as Row[]) {
        const events = (sub.events as string[]) ?? [];
        if (!events.includes(input.eventType)) continue;
        await this.enqueueDelivery(input.workspaceId, outbox.id as string, envelope.eventId, {
          destinationKind: "WEBHOOK", subscriptionId: sub.id as string,
        });
        deliveries += 1;
      }
    }
    for (const extra of input.extraDeliveries ?? []) {
      await this.enqueueDelivery(input.workspaceId, outbox.id as string, envelope.eventId, extra);
      deliveries += 1;
    }
    return { envelope, deliveries };
  }

  async enqueueDelivery(
    workspaceId: string,
    outboxId: string,
    eventId: string,
    dest: { destinationKind: string; integrationId?: string; subscriptionId?: string },
  ) {
    return this.prisma.integrationDelivery.create({
      data: {
        workspaceId,
        outboxId,
        eventId,
        integrationId: dest.integrationId ?? null,
        subscriptionId: dest.subscriptionId ?? null,
        destinationKind: dest.destinationKind,
        attempt: 1,
        status: "PENDING",
        responseMetadata: {},
      },
    });
  }

  async listDeliveries(workspaceId: string, limit = 100) {
    const rows = await this.prisma.integrationDelivery.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
      take: limit,
    });
    return rows;
  }

  async listOutbox(workspaceId: string, status?: string) {
    return this.prisma.securityEventOutbox.findMany({
      where: { workspaceId, ...(status ? { status } : {}) },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
  }
}
