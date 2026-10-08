import { Controller, Get } from "@nestjs/common";
import { API_PREFIX } from "@dsrclone/config";

/**
 * Root info route (outside the API prefix): opening the bare service URL
 * returns a small service descriptor instead of a bare 404, so humans and
 * uptime dashboards landing on the root can find the real endpoints.
 * Carries no data and requires no auth, like the liveness probe.
 */
@Controller()
export class RootController {
  @Get()
  root(): { service: string; status: string; health: string; liveness: string } {
    return {
      service: "dsrclone-api",
      status: "ok",
      health: `/${API_PREFIX}/health`,
      liveness: `/${API_PREFIX}/health/live`,
    };
  }
}
