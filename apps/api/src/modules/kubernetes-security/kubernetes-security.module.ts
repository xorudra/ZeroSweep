import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { SocModule } from "../soc/soc.module";
import { KubernetesSecurityController } from "./kubernetes-security.controller";
import { KubernetesSecurityService } from "./kubernetes-security.service";

@Module({
  imports: [AuditModule, SocModule],
  controllers: [KubernetesSecurityController],
  providers: [KubernetesSecurityService],
  exports: [KubernetesSecurityService],
})
export class KubernetesSecurityModule {}
