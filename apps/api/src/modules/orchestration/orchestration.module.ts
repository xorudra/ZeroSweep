import { Module } from "@nestjs/common";
import { OrchestrationController } from "./orchestration.controller";
import { OrchestrationService } from "./orchestration.service";
import { ScanEventsService } from "./scan-events.service";
import { PlatformOpsModule } from "../platform-ops/platform-ops.module";

@Module({
  imports: [PlatformOpsModule],
  controllers: [OrchestrationController],
  providers: [OrchestrationService, ScanEventsService],
  exports: [ScanEventsService, OrchestrationService],
})
export class OrchestrationModule {}
