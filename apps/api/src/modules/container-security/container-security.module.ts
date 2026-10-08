import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { CloudNativeModule } from "../cloud-native/cloud-native.module";
import { ContainerSecurityController } from "./container-security.controller";
import { ContainerSecurityService } from "./container-security.service";

@Module({
  imports: [AuditModule, CloudNativeModule],
  controllers: [ContainerSecurityController],
  providers: [ContainerSecurityService],
  exports: [ContainerSecurityService],
})
export class ContainerSecurityModule {}
