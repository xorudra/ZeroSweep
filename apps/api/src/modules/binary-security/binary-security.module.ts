import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { OrchestrationModule } from "../orchestration/orchestration.module";
import { BinarySecurityController } from "./binary-security.controller";
import { BinarySecurityService } from "./binary-security.service";

@Module({
  imports: [AuditModule, OrchestrationModule],
  controllers: [BinarySecurityController],
  providers: [BinarySecurityService],
  exports: [BinarySecurityService],
})
export class BinarySecurityModule {}
