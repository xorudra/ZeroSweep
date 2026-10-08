import { Body, Controller, Get, Headers, Param, Post, Query } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { CloudSecurityV2Service } from "./cloud-security-v2.service";

type HeaderMap = Record<string, string | string[] | undefined>;

/**
 * Cloud Security V2 API (Prompt 34 §138). Extends the Prompt 14
 * surface without colliding with it: connection tests, orchestrated
 * assessments, findings, attack paths, snapshots, baselines,
 * coverage, Steampipe packs, NL queries and the report catalog.
 * There is NO endpoint that creates, modifies or deletes a cloud
 * resource, accepts a credential value, or runs a raw query/command.
 */
@Controller()
export class CloudSecurityV2Controller {
  constructor(private readonly service: CloudSecurityV2Service) {}

  @Get("cloud/me/permissions")
  mePermissions(@CurrentUser() user: RequestUser) {
    return this.service.mePermissions(user);
  }

  @Post("cloud/accounts/:id/test")
  testConnection(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.testConnection(user, headers, id);
  }

  @Get("cloud/accounts/:id/connection-tests")
  listConnectionTests(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.listConnectionTests(user, headers, id);
  }

  @Post("cloud/accounts/:id/assess")
  assess(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.assessAccount(user, headers, id, body ?? {});
  }

  @Get("cloud/runs")
  listRuns(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listRuns(user, headers);
  }

  @Get("cloud/findings")
  listFindings(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listFindings(user, headers);
  }

  @Get("cloud/attack-paths")
  listAttackPaths(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.listAttackPaths(user, headers, query ?? {});
  }

  @Get("cloud/resources/:id/snapshots")
  listResourceSnapshots(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.listResourceSnapshots(user, headers, id);
  }

  @Get("cloud/coverage")
  getCoverage(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.getCoverage(user, headers, query ?? {});
  }

  @Post("cloud/baselines")
  createBaseline(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createBaseline(user, headers, body ?? {});
  }

  @Get("cloud/baselines")
  listBaselines(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listBaselines(user, headers);
  }

  @Get("cloud/baseline-drift")
  baselineDrift(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.baselineDrift(user, headers, query ?? {});
  }

  @Get("cloud/steampipe-packs")
  steampipePacks(@CurrentUser() user: RequestUser) {
    return this.service.steampipePacks(user);
  }

  @Post("cloud/steampipe/query")
  runSteampipeQuery(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    return this.service.runSteampipeQuery(user, body ?? {});
  }

  @Post("cloud/nl-query")
  nlQuery(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.nlQuery(user, headers, body ?? {});
  }

  @Get("cloud/reports")
  reports(@CurrentUser() user: RequestUser) {
    return this.service.reports(user);
  }

  @Post("cloud/verification-plan")
  verificationPlan(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    return this.service.verificationPlan(user, body ?? {});
  }
}
