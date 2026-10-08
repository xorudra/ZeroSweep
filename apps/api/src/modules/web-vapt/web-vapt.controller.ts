import { Body, Controller, Get, Headers, Param, Post } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { WebVaptService } from "./web-vapt.service";
import { webVaptPermissionsFor } from "./permissions";

type AuthUser = RequestUser;

/**
 * Web/API VAPT V2 routes (Prompt 32 §165). Every handler delegates to
 * WebVaptService, which enforces the §166/§167 permissions, the §6
 * authorization chain and the §16 HIGH-module gate — the controller
 * itself holds no business logic.
 */
@Controller("vapt")
export class WebVaptController {
  constructor(private readonly service: WebVaptService) {}

  @Get("me/permissions")
  me(@CurrentUser() user: AuthUser) {
    return { permissions: webVaptPermissionsFor(user.role) };
  }

  /* ----- web targets (§165) ----- */
  @Get("web/targets")
  listTargets(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>) {
    return this.service.listTargets(user, headers);
  }

  @Post("web/targets")
  createTarget(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Body() body: Record<string, unknown>) {
    return this.service.createTarget(user, headers, body ?? {});
  }

  @Get("web/targets/:id")
  getTarget(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string) {
    return this.service.getTarget(user, headers, id);
  }

  @Post("web/targets/:id/preflight")
  preflight(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.runPreflight(user, headers, id, body ?? {});
  }

  @Post("web/targets/:id/plans")
  createPlan(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.createPlan(user, headers, id, body ?? {});
  }

  @Get("web/targets/:id/plans")
  listPlans(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string) {
    return this.service.listPlans(user, headers, id);
  }

  @Post("web/targets/:id/scan")
  startScan(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.startScan(user, headers, id, body ?? {});
  }

  /* ----- scans (§165) ----- */
  @Get("scans")
  listScans(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>) {
    return this.service.listScans(user, headers);
  }

  @Get("scans/:id")
  getScan(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string) {
    return this.service.getScan(user, headers, id);
  }

  @Post("scans/:id/cancel")
  cancelScan(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string) {
    return this.service.cancelScan(user, headers, id);
  }

  @Get("scans/:id/coverage")
  coverage(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string) {
    return this.service.getCoverage(user, headers, id);
  }

  /* ----- API services + specifications (§165) ----- */
  @Get("api/services")
  listApiServices(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>) {
    return this.service.listApiServices(user, headers);
  }

  @Post("api/specifications")
  importSpecification(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Body() body: Record<string, unknown>) {
    return this.service.importSpecification(user, headers, body ?? {});
  }

  @Post("api/services/:id/scan")
  startApiScan(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.startApiScan(user, headers, id, body ?? {});
  }

  /* ----- authorization testing (§97–§102) ----- */
  @Post("authorization/test-cases/:id/matrix")
  evaluateMatrix(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.evaluateMatrix(user, headers, id, body ?? {});
  }

  @Post("authorization/scenarios")
  createScenario(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Body() body: Record<string, unknown>) {
    return this.service.createScenario(user, headers, body ?? {});
  }

  @Post("authorization/scenarios/:id/evaluate")
  evaluateScenario(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.evaluateScenario(user, headers, id, body ?? {});
  }

  /* ----- tool health, profiles, AI (§146/§161/§165) ----- */
  @Get("tool-health")
  toolHealth(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>) {
    return this.service.toolHealth(user, headers);
  }

  @Get("profiles")
  profiles(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>) {
    return this.service.listProfiles(user, headers);
  }

  @Post("ai/suggest")
  aiSuggest(@CurrentUser() user: AuthUser, @Headers() headers: Record<string, string | string[] | undefined>, @Body() body: Record<string, unknown>) {
    return this.service.aiSuggest(user, headers, body ?? {});
  }
}
