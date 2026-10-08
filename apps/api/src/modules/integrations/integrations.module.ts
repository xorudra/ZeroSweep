import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { IdentityModule } from "../identity/identity.module";
import { IntegrationsController } from "./integrations.controller";
import { DevSecopsController } from "./devsecops.controller";
import { CicdController } from "./cicd.controller";
import { TicketsController } from "./tickets.controller";
import { WebhooksController } from "./webhooks.controller";
import { IntegrationTransportFactory, IntegrationSecretResolver } from "./core/transport";
import { IntegrationsService } from "./core/integrations.service";
import { RepositoriesIntegrationService } from "./repositories/repositories-integration.service";
import { QualityGatesService } from "./quality-gates/quality-gates.service";
import { ScanTriggerService } from "./cicd/scan-trigger.service";
import { CicdService } from "./cicd/cicd.service";
import { WebhooksService } from "./webhooks/webhooks.service";
import { WebhookSubscriptionsService } from "./webhooks/webhook-subscriptions.service";
import { TicketsService } from "./tickets/tickets.service";
import { MessagingService } from "./messaging/messaging.service";
import { SiemService } from "./siem/siem.service";
import { EventsService } from "./events/events.service";
import { FetchOutboundHttp, OUTBOUND_HTTP, OutboxProcessorService } from "./events/outbox-processor.service";
import { IntegrationHealthService } from "./health/integration-health.service";
import { IntegrationOAuthService } from "./oauth/oauth.service";

/**
 * Prompt 24 — Enterprise Integrations, DevSecOps & Security Workflow
 * Engine. EXPANDS the Prompt 20 integrations module in place: the
 * registry now covers source control, ticketing, messaging, SIEM and
 * generic webhooks; signed inbound webhooks trigger ONLY governed
 * work through OrchestrationService; the transactional outbox fans
 * canonical events out to integrations with bounded, SSRF-guarded
 * delivery. Provider transports are deliberately unwired in this
 * deployment (NOT_CONFIGURED honestly) — see core/transport.ts.
 */
@Module({
  imports: [AuditModule, OrchestrationModule, IdentityModule],
  controllers: [IntegrationsController, DevSecopsController, CicdController, TicketsController, WebhooksController],
  providers: [
    IntegrationTransportFactory,
    IntegrationSecretResolver,
    IntegrationsService,
    RepositoriesIntegrationService,
    QualityGatesService,
    ScanTriggerService,
    CicdService,
    WebhooksService,
    WebhookSubscriptionsService,
    TicketsService,
    MessagingService,
    SiemService,
    EventsService,
    OutboxProcessorService,
    IntegrationHealthService,
    IntegrationOAuthService,
    { provide: OUTBOUND_HTTP, useClass: FetchOutboundHttp },
  ],
  exports: [IntegrationsService, EventsService, OutboxProcessorService, WebhooksService, CicdService],
})
export class IntegrationsModule {}
