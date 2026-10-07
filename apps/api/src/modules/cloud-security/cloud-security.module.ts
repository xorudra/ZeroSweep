import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { CloudSecurityController } from "./cloud-security.controller";
import { CloudSecurityService } from "./cloud-security.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [CloudSecurityController],
  providers: [CloudSecurityService],
  exports: [CloudSecurityService],
})
export class CloudSecurityModule {}
