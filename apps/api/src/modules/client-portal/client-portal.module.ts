import { Module } from "@nestjs/common";
import { ClientAdminController, ClientPortalController, SharedReportController } from "./client-portal.controller";
import { ClientPortalService } from "./client-portal.service";

@Module({
  controllers: [ClientAdminController, ClientPortalController, SharedReportController],
  providers: [ClientPortalService],
  exports: [ClientPortalService],
})
export class ClientPortalModule {}
