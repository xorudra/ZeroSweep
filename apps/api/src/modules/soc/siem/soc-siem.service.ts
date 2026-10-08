import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { SIEM_EVENT_TYPES } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { EventsService } from "../../integrations/events/events.service";
import { requireSocPermission } from "../permissions";
import type { Row } from "../helpers";

/**
 * SOC → SIEM forwarding (Prompt 28 brief + §92; machinery from
 * Prompt 24 §61–§67). SOC events are converted to the SIEM shape and
 * queued as outbox deliveries to the workspace's SIEM integrations —
 * the ONLY egress path. There is no direct HTTP call anywhere in
 * this module: delivery inherits the outbox's signing, SSRF
 * validation (incl. redirect re-validation), retry and dead-letter
 * discipline, and payloads carry references + severities only.
 */
@Injectable()
export class SocSiemService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly events: EventsService,
  ) {}

  /** Forwarding profiles = the workspace's SIEM integrations (P24). */
  async listProfiles(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const items = await this.prisma.integration.findMany({ where: { workspaceId, type: "SIEM" } });
    return {
      items: (items as Row[]).map((i) => ({
        id: i.id, name: i.name, enabled: i.enabled, status: i.status,
        hasSecretReference: Boolean(i.secretReference),
        transport: i.enabled ? "QUEUED_VIA_OUTBOX" : "DISABLED",
      })),
      total: (items as Row[]).length,
      note: "Forwarding profiles are Prompt 24 SIEM integrations; delivery is asynchronous via the governed outbox.",
    };
  }

  async forward(user: RequestUser, workspaceId: string, body: { integrationId: string; kind: "ALERT" | "INCIDENT"; resourceId: string; format?: string }) {
    requireSocPermission(user, "MANAGE_INCIDENTS");
    const integration = await this.prisma.integration.findFirst({
      where: { id: body.integrationId, workspaceId, type: "SIEM" },
    });
    if (!integration) throw new NotFoundException("SIEM integration not found in this workspace");
    const resource = body.kind === "ALERT"
      ? await this.prisma.securityAlert.findFirst({ where: { id: body.resourceId, workspaceId } })
      : await this.prisma.securityIncident.findFirst({ where: { id: body.resourceId, workspaceId } });
    if (!resource) throw new NotFoundException(`${body.kind} not found in this workspace`);
    const row = resource as Row;
    const eventType = body.kind === "ALERT" ? "ALERT_CREATED" : "INCIDENT_DECLARED";
    const { envelope, deliveries } = await this.events.publish({
      workspaceId,
      eventType: `siem.${eventType.toLowerCase()}`,
      resourceType: body.kind === "ALERT" ? "SecurityAlert" : "SecurityIncident",
      resourceId: body.resourceId,
      payload: {
        siemEventType: (SIEM_EVENT_TYPES as readonly string[]).includes(eventType) ? eventType : "FINDING_CREATED",
        severity: row.severity, status: row.status, priority: row.priority,
        title: row.title, format: body.format ?? "JSON",
      },
      extraDeliveries: [{ destinationKind: "SIEM", integrationId: body.integrationId }],
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SIEM_EVENT_EXPORTED", resourceType: "Integration", resourceId: body.integrationId,
      metadata: { eventId: envelope.eventId, socKind: body.kind, resourceId: body.resourceId, queued: deliveries > 0 },
    });
    return { queued: deliveries > 0, eventId: envelope.eventId, detail: "queued in the governed outbox — delivery is asynchronous (§66 discipline from P24)" };
  }
}
