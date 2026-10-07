import { Controller, Get } from "@nestjs/common";
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
}
