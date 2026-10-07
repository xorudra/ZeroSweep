import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { MobileSecurityController } from "./mobile-security.controller";
import { MobileSecurityService } from "./mobile-security.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [MobileSecurityController],
  providers: [MobileSecurityService],
  exports: [MobileSecurityService],
})
export class MobileSecurityModule {}
