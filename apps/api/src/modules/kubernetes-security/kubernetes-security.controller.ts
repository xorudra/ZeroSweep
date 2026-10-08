import { Body, Controller, Get, Headers, Param, Post, Query } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { KubernetesSecurityService } from "./kubernetes-security.service";

type HeaderMap = Record<string, string | string[] | undefined>;

/**
 * Kubernetes Security V2 API (Prompt 34 §4/§138) — distinct routes
 * from the Prompt 13 surface (which keeps cluster registration and
 * gated scans). No endpoint accepts kubeconfig content, reads a
 * Secret value, harvests a token, or acts on a workload.
 */
@Controller()
export class KubernetesSecurityController {
  constructor(private readonly service: KubernetesSecurityService) {}

  @Get("kubernetes/me/permissions")
  mePermissions(@CurrentUser() user: RequestUser) {
    return this.service.mePermissions(user);
  }

  @Post("kubernetes/clusters/:id/assess")
  assessCluster(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.assessCluster(user, headers, id, body ?? {});
  }

  @Post("kubernetes/clusters/:id/rbac")
  importRbac(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.importRbac(user, headers, id, body ?? {});
  }

  @Get("kubernetes/rbac")
  getRbac(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.getRbac(user, headers, String(query.clusterId ?? ""));
  }

  @Get("kubernetes/findings")
  listFindings(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listFindings(user, headers);
  }

  @Get("kubernetes/runtime-events")
  listRuntimeEvents(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.listRuntimeEvents(user, headers, query ?? {});
  }

  @Post("kubernetes/runtime-events/:id/correlate")
  correlateRuntimeEvent(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.correlateRuntimeEvent(user, headers, id);
  }

  @Post("kubernetes/baselines")
  createBaseline(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createBaseline(user, headers, body ?? {});
  }

  @Get("kubernetes/baselines")
  listBaselines(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listBaselines(user, headers);
  }

  @Get("kubernetes/baseline-drift")
  baselineDrift(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.baselineDrift(user, headers, query ?? {});
  }

  @Get("kubernetes/coverage")
  getCoverage(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, unknown>) {
    return this.service.getCoverage(user, headers, query ?? {});
  }

  @Post("kubernetes/verification-plan")
  verificationPlan(@CurrentUser() user: RequestUser, @Body() body: Record<string, unknown>) {
    return this.service.verificationPlan(user, body ?? {});
  }
}
