import { Module } from "@nestjs/common";
import { OrchestrationController } from "./orchestration.controller";
import { OrchestrationService } from "./orchestration.service";
import { ScanEventsService } from "./scan-events.service";

@Module({
  controllers: [OrchestrationController],
  providers: [OrchestrationService, ScanEventsService],
  exports: [ScanEventsService, OrchestrationService],
})
export class OrchestrationModule {}
