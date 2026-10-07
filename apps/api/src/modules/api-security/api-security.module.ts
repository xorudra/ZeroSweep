import { Module } from "@nestjs/common";
import { ApiSecurityController } from "./api-security.controller";
import { ApiSecurityService } from "./api-security.service";

@Module({
  controllers: [ApiSecurityController],
  providers: [ApiSecurityService],
  exports: [ApiSecurityService],
})
export class ApiSecurityModule {}
