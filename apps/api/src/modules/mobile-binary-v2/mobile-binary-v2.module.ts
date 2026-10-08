import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { MobileSecurityModule } from "../mobile-security/mobile-security.module";
import { BinarySecurityModule } from "../binary-security/binary-security.module";
import { MobileBinaryV2Controller } from "./mobile-binary-v2.controller";
import { MobileBinaryV2Service } from "./mobile-binary-v2.service";

/**
 * Prompt 35 — Mobile & Binary Security V2. Deepens Prompts 17/18 by
 * composition: the V1 governed services are imported and delegated
 * to, never replaced.
 */
@Module({
  imports: [AuditModule, MobileSecurityModule, BinarySecurityModule],
  controllers: [MobileBinaryV2Controller],
  providers: [MobileBinaryV2Service],
  exports: [MobileBinaryV2Service],
})
export class MobileBinaryV2Module {}
