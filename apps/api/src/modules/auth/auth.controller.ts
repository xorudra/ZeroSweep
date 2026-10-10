import { Body, Controller, Get, Post, Req } from "@nestjs/common";
import type { Request } from "express";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { clientIp } from "../../common/middleware/request-id.middleware";
import { QueueService } from "../../queue/queue.service";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService, private readonly queue: QueueService) {}

  // A10: the attempt buckets key on clientIp() — the LAST X-Forwarded-For
  // hop — never req.ip's socket address (shared platform edge) and never
  // the client-supplied first XFF entry.
  @Public()
  @Post("register")
  async register(@Body() body: unknown, @Req() req: Request) { return this.auth.register(body, clientIp(req)); }

  @Public()
  @Post("login")
  async login(@Body() body: unknown, @Req() req: Request) { return this.auth.login(body, clientIp(req)); }

  @Get("me")
  async me(@CurrentUser() user: RequestUser) { return this.auth.meProfile(user); }

  /** Harmless queue smoke test — proves the job pipeline; runs no tool. */
  @Post("queue-smoke-test")
  async queueSmokeTest(@CurrentUser() user: RequestUser) {
    const enqueued = await this.queue.enqueuePlaceholder(user.id);
    return { enqueued, note: "Placeholder job only — no security tool is executed." };
  }
}
