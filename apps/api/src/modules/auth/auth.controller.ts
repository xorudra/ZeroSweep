import { Body, Controller, Get, Post, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { clientIp } from "../../common/middleware/request-id.middleware";
import { applySessionCookie, withoutSessionToken } from "../../common/session-cookie";
import { QueueService } from "../../queue/queue.service";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService, private readonly queue: QueueService) {}

  // A10: the attempt buckets key on clientIp() — the edge-observed
  // address (see request-id.middleware: the last XFF hop is honored
  // only when the trusted proxy hop is configured, otherwise the
  // socket/Express peer address), never the client-supplied first
  // XFF entry.
  // A7: successful register/login responses also set the HttpOnly refresh
  // cookie (applySessionCookie mirrors the body's session credential);
  // an MFA-challenge response carries no session and sets nothing.
  // The session credential itself is stripped from the JSON body —
  // it travels only in the HttpOnly cookie.
  @Public()
  @Post("register")
  async register(@Body() body: unknown, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const result = await this.auth.register(body, clientIp(req));
    applySessionCookie(res, result);
    return withoutSessionToken(result as Record<string, unknown>);
  }

  @Public()
  @Post("login")
  async login(@Body() body: unknown, @Req() req: Request, @Res({ passthrough: true }) res: Response) {
    const result = await this.auth.login(body, clientIp(req));
    applySessionCookie(res, result);
    return withoutSessionToken(result as Record<string, unknown>);
  }

  @Get("me")
  async me(@CurrentUser() user: RequestUser) { return this.auth.meProfile(user); }

  /** Harmless queue smoke test — proves the job pipeline; runs no tool. */
  @Post("queue-smoke-test")
  async queueSmokeTest(@CurrentUser() user: RequestUser) {
    const enqueued = await this.queue.enqueuePlaceholder(user.id);
    return { enqueued, note: "Placeholder job only — no security tool is executed." };
  }
}
