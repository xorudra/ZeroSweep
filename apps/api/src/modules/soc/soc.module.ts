import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { IntegrationsModule } from "../integrations/integrations.module";
import { SocController } from "./soc.controller";
import { TelemetryService } from "./telemetry/telemetry.service";
import { IngestionCoordinator } from "./telemetry/ingestion-coordinator.service";
import { DetectionService } from "./detections/detection.service";
import { AlertService } from "./alerts/alert.service";
import { IncidentService } from "./incidents/incident.service";
import { IntelService } from "./threat-intelligence/intel.service";
import { SocCorrelationService } from "./correlation/soc-correlation.service";
import { ResponseService } from "./response/response.service";
import { PlaybookService } from "./playbooks/playbook.service";
import { SocAnalyticsService } from "./analytics/soc-analytics.service";
import { SocHealthService } from "./health/soc-health.service";
import { SocSiemService } from "./siem/soc-siem.service";
import { SocAiService } from "./ai/soc-ai.service";

/**
 * Prompt 28 — Enterprise SOC, SIEM, Detection Engineering, Threat
 * Intelligence & Incident Response. Layers over the existing event
 * bus/outbox (P24), data lake + correlation (P27), notification
 * router (P22) and identity (P23): telemetry lands in a canonical
 * store, declarative detections raise deduped alerts, incidents run
 * an append-only timeline with hash-anchored evidence, and response
 * is a closed catalog of predefined defensive actions behind an
 * approval policy with segregation of duties.
 */
@Module({
  imports: [AuditModule, IntegrationsModule],
  controllers: [SocController],
  providers: [
    TelemetryService, IngestionCoordinator, DetectionService, AlertService,
    IncidentService, IntelService, SocCorrelationService, ResponseService,
    PlaybookService, SocAnalyticsService, SocHealthService, SocSiemService, SocAiService,
  ],
  exports: [TelemetryService, DetectionService, AlertService, IncidentService, IntelService],
})
export class SocModule {}
