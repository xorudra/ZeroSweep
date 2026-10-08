import { Body, Controller, Get, Headers, Param, Post, Query } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { NetworkVaptService } from "./network-vapt.service";

type HeaderMap = Record<string, string | string[] | undefined>;

/** Network VAPT V2 API (Prompt 33 §127/§128). Thin over the service —
 *  all governance lives there and in the SDK. */
@Controller("vapt/network")
export class NetworkVaptController {
  constructor(private readonly service: NetworkVaptService) {}

  @Get("me/permissions")
  mePermissions(@CurrentUser() user: RequestUser) {
    return this.service.mePermissions(user);
  }

  @Get("targets")
  listTargets(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listTargets(user, headers);
  }

  @Post("targets")
  createTarget(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createTarget(user, headers, body ?? {});
  }

  @Get("targets/:id")
  getTarget(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.getTarget(user, headers, id);
  }

  @Post("targets/:id/preflight")
  preflight(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.runPreflight(user, headers, id, body ?? {});
  }

  @Post("targets/:id/plans")
  createPlan(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.createPlan(user, headers, id, body ?? {});
  }

  @Get("targets/:id/plans")
  listPlans(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.listPlans(user, headers, id);
  }

  @Post("targets/:id/scan")
  startScan(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string, @Body() body: Record<string, unknown>) {
    return this.service.startScan(user, headers, id, body ?? {});
  }

  @Get("scans")
  listScans(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listScans(user, headers);
  }

  @Get("scans/:id")
  getScan(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.getScan(user, headers, id);
  }

  @Post("scans/:id/cancel")
  cancelScan(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.cancelScan(user, headers, id);
  }

  @Get("hosts")
  listHosts(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, string | undefined>) {
    return this.service.listHosts(user, headers, query ?? {});
  }

  @Get("hosts/:id")
  getHost(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.getHost(user, headers, id);
  }

  @Post("discoveries")
  recordDiscovery(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.recordDiscovery(user, headers, body ?? {});
  }

  @Get("segments")
  listSegments(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listSegments(user, headers);
  }

  @Post("segments")
  createSegment(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createSegment(user, headers, body ?? {});
  }

  @Post("baselines")
  createBaseline(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createBaseline(user, headers, body ?? {});
  }

  @Get("drift")
  listDrift(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listDrift(user, headers);
  }

  @Post("drift/compute")
  computeDrift(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.computeDrift(user, headers, body ?? {});
  }

  @Get("tool-health")
  toolHealth(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.toolHealth(user, headers);
  }

  @Get("coverage")
  coverage(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.coverage(user, headers);
  }

  @Post("packet-captures")
  createPacketCapture(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.createPacketCapture(user, headers, body ?? {});
  }

  @Get("packet-captures")
  listPacketCaptures(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.listPacketCaptures(user, headers);
  }

  @Get("packet-captures/:id")
  getPacketCapture(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Param("id") id: string) {
    return this.service.getPacketCapture(user, headers, id);
  }

  @Get("exploit-references")
  exploitReferences(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Query() query: Record<string, string | undefined>) {
    return this.service.listExploitReferences(user, headers, query ?? {});
  }

  @Post("metasploit-verifications")
  metasploitVerification(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.requestMetasploitVerification(user, headers, body ?? {});
  }

  @Get("reports/summary")
  reportSummary(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap) {
    return this.service.reportSummary(user, headers);
  }

  @Post("ai/suggest")
  aiSuggest(@CurrentUser() user: RequestUser, @Headers() headers: HeaderMap, @Body() body: Record<string, unknown>) {
    return this.service.aiSuggest(user, headers, body ?? {});
  }
}
