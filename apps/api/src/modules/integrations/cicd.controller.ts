import { Body, Controller, Get, Headers, Param, Post, UnauthorizedException } from "@nestjs/common";
import { Public } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { KeysService } from "../identity/keys/keys.service";
import { createPipelineRunSchema } from "./dto/schemas";
import { CicdService } from "./cicd/cicd.service";

/**
 * CI/CD pipeline endpoints (Prompt 24 §32–§35, §107). These routes
 * are @Public at the JWT layer because pipelines authenticate with
 * scoped API keys instead (§34/§35): `pipelines:security-scan` to
 * request a run, `pipelines:gate-read` to read the verdict. No other
 * credential is accepted, and the key's service account binds the
 * workspace — a pipeline can never address another tenant's runs
 * (§133/§134 discipline).
 */
@Controller("devsecops")
export class CicdController {
  constructor(
    private readonly keys: KeysService,
    private readonly cicd: CicdService,
  ) {}

  private async principal(authorization: string | undefined, scope: string) {
    const token = authorization?.startsWith("Bearer ") ? authorization.slice(7) : "";
    if (!token.startsWith("dsr_live_")) throw new UnauthorizedException("CI endpoints require a DSRclone API key (§35)");
    const auth = await this.keys.authenticateApiKey(token, scope);
    if (!auth.ok) throw new UnauthorizedException(`API key rejected: ${auth.reason}`);
    return auth;
  }

  @Public()
  @Post("pipelines")
  async requestRun(@Headers("authorization") authorization: string | undefined, @Body() body: unknown) {
    const principal = await this.principal(authorization, "pipelines:security-scan");
    return this.cicd.requestPipelineRun(principal, parseOrThrow(createPipelineRunSchema, body ?? {}));
  }

  @Public()
  @Get("pipelines/:id/gate")
  async gate(@Headers("authorization") authorization: string | undefined, @Param("id") id: string) {
    const principal = await this.principal(authorization, "pipelines:gate-read");
    const run = await this.cicd.getPipelineRunForPrincipal(principal, id);
    return {
      id: run.id,
      status: run.status,
      gateResult: run.gateResult,
      blockReason: run.blockReason,
      summary: run.summary,
    };
  }
}
