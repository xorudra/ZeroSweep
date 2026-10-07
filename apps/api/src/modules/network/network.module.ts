import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { NetworkController, ScanNetworkController } from "./network.controller";
import { NetworkService } from "./network.service";

@Module({
  imports: [AuditModule],
  controllers: [NetworkController, ScanNetworkController],
  providers: [NetworkService],
  exports: [NetworkService],
})
export class NetworkModule {}
