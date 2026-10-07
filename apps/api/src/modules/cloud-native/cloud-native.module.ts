import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { CloudNativeController } from "./cloud-native.controller";
import { CloudNativeService } from "./cloud-native.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [CloudNativeController],
  providers: [CloudNativeService],
  exports: [CloudNativeService],
})
export class CloudNativeModule {}
