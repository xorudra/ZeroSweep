import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { WebVaptController } from "./web-vapt.controller";
import { WebVaptService } from "./web-vapt.service";

@Module({
  imports: [AuditModule],
  controllers: [WebVaptController],
  providers: [WebVaptService],
  exports: [WebVaptService],
})
export class WebVaptModule {}
