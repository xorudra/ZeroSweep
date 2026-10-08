import { Inject, Injectable } from "@nestjs/common";
import { SIEM_EVENT_TYPES } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { EventsService } from "../events/events.service";
import type { SiemExportBody } from "../dto/schemas";

type Row = Record<string, unknown>;

/**
 * SIEM export (Prompt 24 §61–§67). Platform events are converted to
 * the §64 SIEM shape (references + scores only) and queued as outbox
 * deliveries to the workspace's SIEM integrations. Export is ALWAYS
 * asynchronous (§66): a SIEM outage can never block a scan, a
 * report, or this API call — the outbox retries with backoff and
 * dead-letters in a bounded way.
 */
@Injectable()
export class SiemService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly events: EventsService,
  ) {}

  async exportEvent(user: RequestUser, workspaceId: string, body: SiemExportBody) {
    requireIntegrationPermission(user, "MANAGE_SIEM_INTEGRATIONS");
    const integration = await this.prisma.integration.findFirst({
      where: { id: body.integrationId, workspaceId, type: "SIEM" },
    });
    if (!integration) return { queued: false, detail: "SIEM integration not found in this workspace" };
    const eventType = body.eventType as string;
    const { envelope, deliveries } = await this.events.publish({
      workspaceId,
      eventType: `siem.${eventType.toLowerCase()}`,
      resourceType: body.findingId ? "Finding" : "SecurityEvent",
      resourceId: (body.findingId as string) ?? (body.assetReference as string) ?? "security-event",
      payload: {
        siemEventType: (SIEM_EVENT_TYPES as readonly string[]).includes(eventType) ? eventType : "FINDING_CREATED",
        severity: body.severity, status: body.status,
        findingId: body.findingId, assetReference: body.assetReference,
        riskScore: body.riskScore, cve: body.cve, cwe: body.cwe,
        format: body.format ?? ((integration.configuration ?? integration.config ?? {}) as Row).format ?? "JSON",
      },
      extraDeliveries: [{ destinationKind: "SIEM", integrationId: integration.id as string }],
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SIEM_EVENT_EXPORTED", resourceType: "Integration", resourceId: integration.id as string,
      metadata: { eventId: envelope.eventId, siemEventType: eventType, queued: deliveries > 0 },
    });
    return { queued: deliveries > 0, eventId: envelope.eventId, detail: "event queued in the outbox — delivery is asynchronous and outage-tolerant (§66)" };
  }
}
