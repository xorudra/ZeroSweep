import { Controller, Get, Header } from "@nestjs/common";
import { Public } from "../common/decorators/auth.decorators";
import { MetricsService } from "./metrics.service";

/** Prometheus scrape endpoint (Prompt 25 §102). Deployments restrict it via
 *  NetworkPolicy to the monitoring namespace — it is never Internet-exposed. */
@Controller("metrics")
export class MetricsController {
  constructor(private readonly metrics: MetricsService) {}

  @Public()
  @Get()
  @Header("content-type", "text/plain; version=0.0.4; charset=utf-8")
  async scrape(): Promise<string> {
    return this.metrics.render();
  }
}
