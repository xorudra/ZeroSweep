import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { HealthModule } from "../../health/health.module";
import { PlatformController } from "./platform.controller";
import { PlatformControlService } from "./platform-control.service";
import { PlatformOverviewService } from "./platform-overview.service";
import { BackupService } from "./backup.service";
import { ProductionConfigurationService } from "./production-config.service";

/**
 * Prompt 38 platform operations module. PlatformControlService is
 * exported so enforcement points (scan start in OrchestrationModule)
 * share the one control-plane state — there is exactly one kill-switch
 * store for the platform.
 */
@Module({
  imports: [AuditModule, HealthModule],
  controllers: [PlatformController],
  providers: [PlatformControlService, PlatformOverviewService, BackupService, ProductionConfigurationService],
  exports: [PlatformControlService, ProductionConfigurationService],
})
export class PlatformOpsModule {}
