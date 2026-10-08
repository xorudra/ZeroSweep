import { Body, Controller, Get, Post, Req } from "@nestjs/common";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { QueueService } from "../../queue/queue.service";
import { AuthService } from "./auth.service";

@Controller("auth")
export class AuthController {
  constructor(private readonly auth: AuthService, private readonly queue: QueueService) {}

  @Public()
  @Post("register")
  async register(@Body() body: unknown) { return this.auth.register(body); }

  @Public()
  @Post("login")
  async login(@Body() body: unknown, @Req() req: { ip?: string }) { return this.auth.login(body, req?.ip ?? "unknown"); }

  @Get("me")
  async me(@CurrentUser() user: RequestUser) { return user; }

  /** Harmless queue smoke test — proves the job pipeline; runs no tool. */
  @Post("queue-smoke-test")
  async queueSmokeTest(@CurrentUser() user: RequestUser) {
    const enqueued = await this.queue.enqueuePlaceholder(user.id);
    return { enqueued, note: "Placeholder job only — no security tool is executed." };
  }
}
