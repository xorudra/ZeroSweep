import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { CloudSecurityV2Controller } from "./cloud-security-v2.controller";
import { CloudSecurityV2Service } from "./cloud-security-v2.service";

@Module({
  imports: [AuditModule],
  controllers: [CloudSecurityV2Controller],
  providers: [CloudSecurityV2Service],
  exports: [CloudSecurityV2Service],
})
export class CloudSecurityV2Module {}
