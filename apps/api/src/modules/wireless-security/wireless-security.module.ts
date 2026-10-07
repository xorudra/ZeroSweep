import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { WirelessSecurityController } from "./wireless-security.controller";
import { WirelessSecurityService } from "./wireless-security.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [WirelessSecurityController],
  providers: [WirelessSecurityService],
  exports: [WirelessSecurityService],
})
export class WirelessSecurityModule {}
