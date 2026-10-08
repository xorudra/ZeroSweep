import { Module } from "@nestjs/common";
import { HealthController } from "./health.controller";
import { HealthService } from "./health.service";
import { MetricsController } from "./metrics.controller";
import { MetricsService } from "./metrics.service";

@Module({
  controllers: [HealthController, MetricsController],
  providers: [HealthService, MetricsService],
  exports: [MetricsService, HealthService],
})
export class HealthModule {}
