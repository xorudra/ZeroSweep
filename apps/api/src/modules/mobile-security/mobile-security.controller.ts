import { Body, Controller, Get, Param, Post } from "@nestjs/common";
import { z } from "zod";
import {
  createMobileDynamicSessionSchema, registerMobileAppSchema, registerMobileDeviceSchema,
  startMobileScanSchema, uploadMobileBuildSchema,
} from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { MobileSecurityService } from "./mobile-security.service";

const dynamicSessionBodySchema = createMobileDynamicSessionSchema.extend({
  // §59/§72/§110: a request may CARRY a script body or shell command
  // so the refusal is explicit + audited (MOBILE_DYNAMIC_ACTION_
  // BLOCKED) — these fields are never executed, never stored.
  scriptBody: z.string().max(20000).optional(),
  shellCommand: z.string().max(2000).optional(),
});

/**
 * Mobile security endpoints (Prompt 17 §100). Registration, build
 * intake, gated scan starts and governed dynamic-session requests
 * are the only writes; everything else is a tenant-scoped read.
 * There is NO endpoint that installs or runs an app, opens a device
 * shell, accepts a Frida script or Objection command, installs a CA,
 * or returns a raw secret value or traffic body — those capabilities
 * do not exist in ZeroSweep (§59/§67/§72/§75/§119).
 */
@Controller()
export class MobileSecurityController {
  constructor(private readonly mobile: MobileSecurityService) {}

  // Applications (§93)
  @Get("mobile/apps")
  async listApps(@CurrentUser() user: RequestUser) {
    return this.mobile.listApps(user);
  }

  @Post("mobile/apps")
  async registerApp(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerMobileAppSchema, body ?? {});
    return this.mobile.registerApp(user, input);
  }

  @Get("mobile/apps/:id")
  async getApp(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.mobile.getApp(user, id);
  }

  // Builds (§94/§95)
  @Post("mobile/apps/:id/builds")
  async uploadBuild(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(uploadMobileBuildSchema, body ?? {});
    return this.mobile.uploadBuild(user, id, input);
  }

  @Get("mobile/builds/:id")
  async getBuild(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.mobile.getBuild(user, id);
  }

  @Get("mobile/builds/:id/artifacts")
  async getBuildArtifacts(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.mobile.getBuildArtifacts(user, id);
  }

  // Scans (§100)
  @Post("mobile/apps/:id/scan")
  async startScan(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startMobileScanSchema, body ?? {});
    return this.mobile.startScan(user, id, input);
  }

  @Post("mobile/builds/:id/scan")
  async startBuildScan(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startMobileScanSchema, body ?? {});
    const build = await this.mobile.getBuild(user, id);
    return this.mobile.startScan(user, build.applicationId, { ...input, buildId: id });
  }

  @Get("mobile/builds/:id/findings")
  async listBuildFindings(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.mobile.listBuildFindings(user, id);
  }

  @Get("mobile/builds/:id/endpoints")
  async listBuildEndpoints(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.mobile.listBuildEndpoints(user, id);
  }

  // Dynamic sessions (§58/§73)
  @Post("mobile/apps/:id/dynamic-session")
  async createDynamicSession(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(dynamicSessionBodySchema, body ?? {});
    return this.mobile.createDynamicSession(user, id, input);
  }

  @Post("mobile/builds/:id/dynamic-session")
  async createBuildDynamicSession(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(dynamicSessionBodySchema, body ?? {});
    const build = await this.mobile.getBuild(user, id);
    return this.mobile.createDynamicSession(user, build.applicationId, { ...input, buildId: id });
  }

  // Device lab (§98)
  @Get("mobile/devices")
  async listDevices(@CurrentUser() user: RequestUser) {
    return this.mobile.listDevices(user);
  }

  @Post("mobile/devices")
  async registerDevice(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerMobileDeviceSchema, body ?? {});
    return this.mobile.registerDevice(user, input);
  }

  // Traffic (§99)
  @Get("mobile/traffic-sessions/:id")
  async getTrafficSession(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.mobile.getTrafficSession(user, id);
  }

  // Tool health (§102)
  @Get("mobile/tools")
  async listTools(@CurrentUser() user: RequestUser) {
    return this.mobile.listTools(user);
  }
}
