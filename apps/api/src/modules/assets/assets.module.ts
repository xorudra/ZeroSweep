import { Module } from "@nestjs/common";
import { AssetsController, EndpointsController } from "./assets.controller";
import { AssetsService } from "./assets.service";

@Module({
  controllers: [AssetsController, EndpointsController],
  providers: [AssetsService],
  exports: [AssetsService],
})
export class AssetsModule {}
