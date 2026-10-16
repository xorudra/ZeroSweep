import { Controller, Headers, Param, Post, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";
import { Public } from "../../common/decorators/auth.decorators";
import { WebhooksService } from "./webhooks/webhooks.service";

/**
 * Inbound provider webhook endpoints (Prompt 24 §108). @Public at
 * the JWT layer BY DESIGN: authentication is the provider signature
 * itself, verified inside the service before any payload field is
 * trusted (§15). The raw body is captured by the webhook middleware
 * in main.ts — HMAC verification needs the exact bytes received.
 */
@Controller("webhooks")
export class WebhooksController {
  constructor(private readonly webhooks: WebhooksService) {}

  @Public()
  @Post("github")
  async github(@Req() req: Request, @Headers() headers: Record<string, string | undefined>, @Res() res: Response) {
    return this.handle("GITHUB", req, headers, res);
  }

  @Public()
  @Post("gitlab")
  async gitlab(@Req() req: Request, @Headers() headers: Record<string, string | undefined>, @Res() res: Response) {
    return this.handle("GITLAB", req, headers, res);
  }

  @Public()
  @Post("bitbucket")
  async bitbucket(@Req() req: Request, @Headers() headers: Record<string, string | undefined>, @Res() res: Response) {
    return this.handle("BITBUCKET", req, headers, res);
  }

  // Tenant-bound routes: the integration id in the path disambiguates
  // attribution to a single integration BEFORE secret trial (audit:
  // inbound-global-secret-match). The legacy provider-only routes
  // stay for compatibility; the service rejects ambiguous matches.
  @Public()
  @Post("github/:integrationId")
  async githubScoped(@Param("integrationId") integrationId: string, @Req() req: Request, @Headers() headers: Record<string, string | undefined>, @Res() res: Response) {
    return this.handle("GITHUB", req, headers, res, integrationId);
  }

  @Public()
  @Post("gitlab/:integrationId")
  async gitlabScoped(@Param("integrationId") integrationId: string, @Req() req: Request, @Headers() headers: Record<string, string | undefined>, @Res() res: Response) {
    return this.handle("GITLAB", req, headers, res, integrationId);
  }

  @Public()
  @Post("bitbucket/:integrationId")
  async bitbucketScoped(@Param("integrationId") integrationId: string, @Req() req: Request, @Headers() headers: Record<string, string | undefined>, @Res() res: Response) {
    return this.handle("BITBUCKET", req, headers, res, integrationId);
  }

  private async handle(
    provider: "GITHUB" | "GITLAB" | "BITBUCKET",
    req: Request,
    headers: Record<string, string | undefined>,
    res: Response,
    integrationId?: string,
  ) {
    const rawBody = (req as Request & { rawBody?: string }).rawBody
      ?? (typeof req.body === "string" ? req.body : JSON.stringify(req.body ?? {}));
    const receipt = await this.webhooks.receive(provider, headers, rawBody, integrationId);
    res.status(receipt.httpStatus).json({
      status: receipt.status,
      reasonCode: receipt.reasonCode ?? null,
      detail: receipt.detail,
      assessmentId: receipt.assessmentId ?? null,
      scanId: receipt.scanId ?? null,
    });
  }
}
