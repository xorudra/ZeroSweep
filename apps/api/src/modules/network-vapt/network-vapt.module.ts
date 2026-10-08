import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { NetworkVaptController } from "./network-vapt.controller";
import { NetworkVaptService } from "./network-vapt.service";

@Module({
  imports: [AuditModule],
  controllers: [NetworkVaptController],
  providers: [NetworkVaptService],
  exports: [NetworkVaptService],
})
export class NetworkVaptModule {}
