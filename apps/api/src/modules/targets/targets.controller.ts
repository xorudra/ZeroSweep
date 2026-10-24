import { Body, Controller, Get, Param, Post, Query, Req } from "@nestjs/common";
import { z } from "zod";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { TargetsService } from "./targets.service";

const verificationSchema = z.object({ method: z.enum(["DNS_TXT", "HTTP_FILE", "MANUAL_APPROVAL"]).default("DNS_TXT") });
const checkSchema = z.object({ declarationAccepted: z.boolean().optional() });

@Controller("targets")
export class TargetsController {
  constructor(private readonly targets: TargetsService) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query() query: unknown) { return this.targets.list(user, query); }

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) { return this.targets.create(user, body); }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) { return this.targets.get(user, id); }

  @Get(":id/verifications")
  async listVerifications(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.targets.listVerifications(user, id);
  }

  @Post(":id/verifications")
  async startVerification(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const { method } = parseOrThrow(verificationSchema, body ?? {});
    return this.targets.startVerification(user, id, method ?? "DNS_TXT");
  }

  @Post(":id/verifications/:verificationId/check")
  async checkVerification(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("verificationId") verificationId: string, @Body() body: unknown, @Req() req: { ip?: string }) {
    const { declarationAccepted } = parseOrThrow(checkSchema, body ?? {});
    // Trust proxy is 1 (main.ts), so req.ip is the last X-Forwarded-For
    // hop — the address the platform edge actually observed, not a
    // client-supplied first entry. Stored only on the verification row.
    return this.targets.checkVerification(user, id, verificationId, { declarationAccepted, clientIp: req.ip });
  }
}
