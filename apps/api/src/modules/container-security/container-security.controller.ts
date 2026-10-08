import { Body, Controller, Get, Headers, Param, Post } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { ContainerSecurityService } from "./container-security.service";

type HeaderMap = Record<string, string | string[] | undefined>;

/**
 * Container Security V2 API (Prompt 34 §3/§138) at the spec's
 * /container routes — distinct from the Prompt 13 /container-images
 * surface, which remains the governed scan/SBOM path this module
 * delegates to. No endpoint pulls, runs or modifies an image.
 */
@Controller()
export class ContainerSecurityController {
  constructor(private readonly service: ContainerSecurityService) {}

  @Get("container/me/permissions")
  mePermissions(@CurrentUser() user: RequestUser) {
    return this.service.mePermissions(user);
  }

  @Get("container/images")
  listImages(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listImages(user, headers);
  }

  @Post("container/images/:id/scan")
  scanImage(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.scanImage(user, id, body ?? {});
  }

  @Get("container/images/:id/sbom")
  getImageSbom(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.service.getImageSbom(user, id);
  }

  @Post("container/images/:id/assess")
  assessImage(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.assessImage(user, headers, id, body ?? {});
  }

  @Post("container/baselines")
  createBaseline(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createBaseline(user, headers, body ?? {});
  }

  @Get("container/baselines")
  listBaselines(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listBaselines(user, headers);
  }

  @Get("container/baseline-drift")
  baselineDrift(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.baselineDrift(user, headers);
  }

  @Get("container/coverage")
  getCoverage(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.getCoverage(user, headers);
  }

  @Get("container/verification-plan")
  verificationPlan(@CurrentUser() user: RequestUser) {
    return this.service.verificationPlan(user);
  }
}
