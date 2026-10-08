import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { ProductModule } from "../product/product.module";
import { PlatformControlController } from "./platform-control.controller";
import { PlatformControlDataService } from "./platform-control.service";

/**
 * Prompt 40 platform control plane (§95): platform-level administration
 * of organizations, subscriptions, licenses, usage, trials, features,
 * plans and support access — separate from tenant administration and
 * guarded by the platform-admin flag + §136 permissions.
 */
@Module({
  imports: [AuditModule, ProductModule],
  controllers: [PlatformControlController],
  providers: [PlatformControlDataService],
  exports: [PlatformControlDataService],
})
export class PlatformControlModule {}
