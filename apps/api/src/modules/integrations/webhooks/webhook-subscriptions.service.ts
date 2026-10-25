import { BadRequestException, Inject, Injectable, NotFoundException, Optional } from "@nestjs/common";
import {
  WEBHOOK_EVENT_TYPES,
  validateWebhookDestination,
  type HostResolver,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { assertSecretReferenceAllowed } from "../core/reference-guard";
import { dnsResolver } from "../../continuous-security/notifications/notification-router.service";
import type { CreateWebhookSubscriptionBody } from "../dto/schemas";

/**
 * Outbound webhook subscriptions (Prompt 24 §68–§74). Destinations
 * are validated at creation AND re-validated with fresh DNS at every
 * delivery (§70): HTTPS only, no credentials in URL, and loopback /
 * link-local / cloud-metadata / private destinations refused via the
 * Prompt 22 SSRF validator.
 */
@Injectable()
export class WebhookSubscriptionsService {
  /** DNS seam — tests inject a fake resolver; no network in tests. */
  resolver: HostResolver;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    @Optional() resolver?: HostResolver,
  ) {
    this.resolver = resolver ?? dnsResolver;
  }

  async create(user: RequestUser, workspaceId: string, body: CreateWebhookSubscriptionBody) {
    requireIntegrationPermission(user, "CREATE_INTEGRATION");
    assertSecretReferenceAllowed(body.secretReference);
    const events = (body.events as string[]) ?? [];
    const unknown = events.filter((e) => !(WEBHOOK_EVENT_TYPES as readonly string[]).includes(e));
    if (unknown.length > 0) {
      throw new BadRequestException(`Unknown webhook event types: ${unknown.join(", ")} (§73 lists the supported events)`);
    }
    const verdict = await validateWebhookDestination({
      url: body.endpoint as string,
      allowlist: [],
      resolver: this.resolver,
    });
    if (!verdict.ok) {
      throw new BadRequestException(`Webhook destination refused: ${verdict.message}`);
    }
    const row = await this.prisma.webhookSubscription.create({
      data: {
        workspaceId,
        endpoint: body.endpoint,
        events,
        secretReference: (body.secretReference as string) ?? null,
        enabled: (body.enabled as boolean) ?? true,
        createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "INTEGRATION_CREATED", resourceType: "WebhookSubscription", resourceId: row.id as string,
      metadata: { events, secretConfigured: Boolean(body.secretReference) },
    });
    return this.present(row as Record<string, unknown>);
  }

  async list(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const rows = await this.prisma.webhookSubscription.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
    });
    return rows.map((r) => this.present(r as Record<string, unknown>));
  }

  async remove(user: RequestUser, workspaceId: string, id: string) {
    requireIntegrationPermission(user, "DELETE_INTEGRATION");
    const row = await this.prisma.webhookSubscription.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Webhook subscription not found");
    await this.prisma.webhookSubscription.delete({ where: { id } });
    return { deleted: true };
  }

  present(row: Record<string, unknown>) {
    return {
      id: row.id,
      workspaceId: row.workspaceId,
      endpoint: row.endpoint,
      events: row.events ?? [],
      secretConfigured: Boolean(row.secretReference),
      secretReference: row.secretReference ?? null,
      enabled: row.enabled !== false,
      createdAt: row.createdAt,
    };
  }
}
