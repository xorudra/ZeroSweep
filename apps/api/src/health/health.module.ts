import { Module } from "@nestjs/common";
import { HealthController } from "./health.controller";
import { RootController } from "./root.controller";
import { HealthService } from "./health.service";
import { MetricsController } from "./metrics.controller";
import { MetricsService } from "./metrics.service";

@Module({
  controllers: [HealthController, MetricsController, RootController],
  providers: [HealthService, MetricsService],
  exports: [MetricsService, HealthService],
})
export class HealthModule {}
