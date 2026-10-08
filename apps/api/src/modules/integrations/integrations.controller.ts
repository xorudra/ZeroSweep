import { Body, Controller, Delete, Get, Inject, Param, Patch, Post } from "@nestjs/common";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import {
  createIntegrationSchema, createJiraMappingSchema, createWebhookSubscriptionSchema,
  rotateCredentialSchema, siemExportSchema, updateIntegrationSchema,
} from "./dto/schemas";
import { IntegrationsService } from "./core/integrations.service";
import { RepositoriesIntegrationService } from "./repositories/repositories-integration.service";
import { WebhookSubscriptionsService } from "./webhooks/webhook-subscriptions.service";
import { IntegrationHealthService } from "./health/integration-health.service";
import { IntegrationOAuthService } from "./oauth/oauth.service";
import { EventsService } from "./events/events.service";
import { OutboxProcessorService } from "./events/outbox-processor.service";
import { TicketsService } from "./tickets/tickets.service";
import { SiemService } from "./siem/siem.service";
import { MessagingService } from "./messaging/messaging.service";

/**
 * Enterprise integrations API (Prompt 24 §107). The pre-Prompt-24
 * routes (GET/POST /integrations) keep their paths and response
 * contract; Prompt 24 widens the surface in place.
 */
@Controller("integrations")
export class IntegrationsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly integrations: IntegrationsService,
    private readonly repositories: RepositoriesIntegrationService,
    private readonly subscriptions: WebhookSubscriptionsService,
    private readonly health: IntegrationHealthService,
    private readonly oauth: IntegrationOAuthService,
    private readonly events: EventsService,
    private readonly processor: OutboxProcessorService,
    private readonly tickets: TicketsService,
    private readonly siem: SiemService,
    private readonly messaging: MessagingService,
  ) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.integrations.list(user, ws.id);
  }

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    // Historical contract: Integrations are created from non-secret
    // config + a secret reference — never inline API keys. The
    // Prompt 24 schema enforces this structurally (§7).
    return this.integrations.create(user, ws.id, parseOrThrow(createIntegrationSchema, body ?? {}));
  }

  @Get("health")
  async healthOverview(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.health.overview(user, ws.id);
  }

  @Get("deliveries")
  async deliveries(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.events.listDeliveries(ws.id);
  }

  @Get("outbox")
  async outbox(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.events.listOutbox(ws.id);
  }

  @Post("outbox/process")
  async processOutbox(@CurrentUser() user: RequestUser) {
    await resolveWorkspace(this.prisma, user);
    return this.processor.processDue();
  }

  @Get("webhook-subscriptions")
  async listSubscriptions(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.subscriptions.list(user, ws.id);
  }

  @Post("webhook-subscriptions")
  async createSubscription(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.subscriptions.create(user, ws.id, parseOrThrow(createWebhookSubscriptionSchema, body ?? {}));
  }

  @Delete("webhook-subscriptions/:id")
  async deleteSubscription(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.subscriptions.remove(user, ws.id, id);
  }

  @Get("jira-mappings")
  async listMappings(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.tickets.listMappings(user, ws.id);
  }

  @Post("jira-mappings")
  async createMapping(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.tickets.createMapping(user, ws.id, parseOrThrow(createJiraMappingSchema, body ?? {}));
  }

  @Post("oauth/:type/begin")
  async beginOAuth(@CurrentUser() user: RequestUser, @Param("type") type: string) {
    return this.oauth.beginFlow(user, type.toUpperCase());
  }

  @Post("oauth/flows/:flowId/complete")
  async completeOAuth(@CurrentUser() user: RequestUser, @Param("flowId") flowId: string, @Body() body: unknown) {
    return this.oauth.completeFlow(user, flowId, (body ?? {}) as Record<string, unknown>);
  }

  @Post("siem/export")
  async siemExport(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.siem.exportEvent(user, ws.id, parseOrThrow(siemExportSchema, body ?? {}));
  }

  @Post("findings/:findingId/messaging-alert")
  async messagingAlert(@CurrentUser() user: RequestUser, @Param("findingId") findingId: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.messaging.sendFindingAlert(user, ws.id, findingId);
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.integrations.get(user, ws.id, id);
  }

  @Patch(":id")
  async update(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.integrations.update(user, ws.id, id, parseOrThrow(updateIntegrationSchema, body ?? {}));
  }

  @Delete(":id")
  async remove(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.integrations.remove(user, ws.id, id);
  }

  @Post(":id/test")
  async test(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.integrations.test(user, ws.id, id);
  }

  @Post(":id/rotate-credential")
  async rotate(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.integrations.rotateCredential(user, ws.id, id, parseOrThrow(rotateCredentialSchema, body ?? {}));
  }

  @Post(":id/sync")
  async sync(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.repositories.syncRepositories(user, ws.id, id);
  }
}
