import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { SocModule } from "../soc/soc.module";
import { EasmController } from "./easm.controller";
import { EasmProgramsService } from "./programs/programs.service";
import { EasmDiscoveryService } from "./discovery/discovery.service";
import { EasmAssetsService } from "./assets/assets.service";
import { EasmDriftService } from "./drift/drift.service";
import { EasmAnalyticsService } from "./analytics/analytics.service";
import { EasmAiService } from "./ai/ai.service";
import { EasmReportsService } from "./reports/reports.service";
import { EasmMonitoringService } from "./monitoring/monitoring.service";
import { EASM_TRANSPORT, UnconfiguredEasmTransport } from "./discovery/transport";

/**
 * Prompt 29 — Enterprise External Attack Surface Management.
 * Layers over the existing asset inventory, RiskEngine V3 context
 * (signals only — §77), Prompt 22 scheduler, Prompt 27 correlation
 * fingerprints, and the Prompt 28 SOC alert path. The authorization
 * boundary is structural: discovery produces CANDIDATES whose
 * activeTestingStatus stays NOT_AUTHORIZED until a separate,
 * separately-permissioned grant is recorded for a VERIFIED root.
 */
@Module({
  imports: [AuditModule, SocModule],
  controllers: [EasmController],
  providers: [
    EasmProgramsService, EasmDiscoveryService, EasmAssetsService, EasmDriftService,
    EasmAnalyticsService, EasmAiService, EasmReportsService, EasmMonitoringService,
    { provide: EASM_TRANSPORT, useClass: UnconfiguredEasmTransport },
  ],
  exports: [EasmProgramsService, EasmDiscoveryService, EasmAssetsService],
})
export class EasmModule {}
