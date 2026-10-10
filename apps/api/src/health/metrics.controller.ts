import { Controller, Get, Header, Headers, NotFoundException } from "@nestjs/common";
import { timingSafeEqual } from "node:crypto";
import { loadEnv } from "@dsrclone/config";
import { Public } from "../common/decorators/auth.decorators";
import { MetricsService } from "./metrics.service";

/** Prometheus scrape endpoint (Prompt 25 §102). The original design assumed
 *  deployments restrict it via NetworkPolicy — on a public hosted
 *  deployment nothing does, so the endpoint gates itself: it answers
 *  only to a Bearer METRICS_TOKEN, and 404s (invisible) when no token
 *  is configured or the presented token does not match. */
@Controller("metrics")
export class MetricsController {
  constructor(private readonly metrics: MetricsService) {}

  @Public()
  @Get()
  @Header("content-type", "text/plain; version=0.0.4; charset=utf-8")
  async scrape(@Headers("authorization") authorization?: string): Promise<string> {
    const expected = loadEnv().METRICS_TOKEN;
    if (!expected) throw new NotFoundException();
    const presented = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
    const a = Buffer.from(presented);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !timingSafeEqual(a, b)) throw new NotFoundException();
    return this.metrics.render();
  }
}
