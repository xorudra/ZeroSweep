import { Module } from "@nestjs/common";
import { ScanHttpHistoryController, ScannersController } from "./scanners.controller";
import { ScannersService } from "./scanners.service";

@Module({
  controllers: [ScannersController, ScanHttpHistoryController],
  providers: [ScannersService],
  exports: [ScannersService],
})
export class ScannersModule {}
