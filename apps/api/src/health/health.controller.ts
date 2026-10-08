import { Controller, Get, Res } from "@nestjs/common";
import type { Response } from "express";
import { Public } from "../common/decorators/auth.decorators";
import { HealthService } from "./health.service";

@Controller("health")
export class HealthController {
  constructor(private readonly health: HealthService) {}
  @Public()
  @Get()
  async getHealth() {
    return this.health.check();
  }

  /**
   * Liveness (Prompt 25 §86/§88): process-level only. NEVER fails because a
   * database, queue, object store or external provider is down — a failing
   * liveness probe would restart healthy processes during an outage.
   */
  @Public()
  @Get("live")
  live() {
    return this.health.live();
  }

  /**
   * Readiness (Prompt 25 §86/§89): 200 only when REQUIRED dependencies
   * (PostgreSQL, Redis) are reachable. Optional dependencies (object
   * storage, AI service, external providers) are reported but never make
   * the instance unready on their own.
   */
  @Public()
  @Get("ready")
  async ready(@Res({ passthrough: true }) res: Response) {
    const report = await this.health.ready();
    res.status(report.ready ? 200 : 503);
    return report;
  }
}
