import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { ActiveDirectoryController } from "./active-directory.controller";
import { ActiveDirectoryService } from "./active-directory.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [ActiveDirectoryController],
  providers: [ActiveDirectoryService],
  exports: [ActiveDirectoryService],
})
export class ActiveDirectoryModule {}
