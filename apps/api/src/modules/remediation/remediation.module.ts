import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { VulnerabilitiesModule } from "../vulnerabilities/vulnerabilities.module";
import { ContinuousSecurityModule } from "../continuous-security/continuous-security.module";
import { IntegrationsModule } from "../integrations/integrations.module";
import { RemediationController } from "./remediation.controller";
import { CaseStateService } from "./case-state.service";
import { RemediationCasesService } from "./cases.service";
import { TriageService } from "./triage.service";
import { OwnershipService } from "./ownership.service";
import { RemediationSlaService } from "./sla.service";
import { RemediationPlansService } from "./plans.service";
import {
  RemediationTicketsService, TICKET_PROVIDERS, UnconfiguredTicketProvider,
  type RemediationTicketProvider, type TicketProviderRegistry,
} from "./tickets.service";
import { RemediationVerificationService } from "./verification.service";
import { RemediationClosureService } from "./closure.service";
import { RemediationExceptionsService } from "./exceptions.service";
import { RemediationCampaignsService } from "./campaigns.service";
import { RemediationRegressionService } from "./regression.service";
import { RemediationAnalyticsService } from "./analytics.service";
import { RemediationAiService } from "./ai.service";
import { RemediationReportsService } from "./reports.service";
import { RemediationBulkService } from "./bulk.service";
import { RemediationTickService } from "./tick.service";

/**
 * Prompt 31 — remediation orchestration. Ticket providers default to
 * the honest NOT_CONFIGURED implementation: no external ticket system
 * is wired in this deployment (P24 connectors), and work items record
 * that truth with retry state rather than fabricating tickets.
 */
@Module({
  imports: [AuditModule, VulnerabilitiesModule, ContinuousSecurityModule, IntegrationsModule],
  controllers: [RemediationController],
  providers: [
    CaseStateService,
    RemediationCasesService,
    TriageService,
    OwnershipService,
    RemediationSlaService,
    RemediationPlansService,
    RemediationTicketsService,
    RemediationVerificationService,
    RemediationClosureService,
    RemediationExceptionsService,
    RemediationCampaignsService,
    RemediationRegressionService,
    RemediationAnalyticsService,
    RemediationAiService,
    RemediationReportsService,
    RemediationBulkService,
    RemediationTickService,
    {
      provide: TICKET_PROVIDERS,
      useFactory: (): TicketProviderRegistry => {
        const unconfigured = new UnconfiguredTicketProvider();
        const registry: TicketProviderRegistry = new Map<string, RemediationTicketProvider>();
        for (const name of ["JIRA", "GITHUB", "GITLAB", "SERVICENOW"]) registry.set(name, unconfigured);
        return registry;
      },
    },
  ],
  exports: [RemediationCasesService, RemediationTickService],
})
export class RemediationModule {}
