import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";
import {
  approveWirelessCaptureSchema, createApprovedWirelessProfileSchema,
  createWirelessEnvironmentSchema, registerWirelessSensorSchema,
  requestWirelessLabValidationSchema, startWirelessScanSchema, uploadWirelessCaptureSchema,
} from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { WirelessSecurityService } from "./wireless-security.service";

/**
 * Wireless security endpoints (Prompt 19 §77). Environment, sensor,
 * capture, approved-profile and lab-validation writes plus
 * tenant-scoped reads are the whole surface. There is NO endpoint
 * that transmits, deauthenticates, triggers handshakes, cracks keys,
 * creates a rogue AP, accepts a raw wireless command or arbitrary
 * tool arguments (§78) — those capabilities do not exist in ZeroSweep.
 */
@Controller()
export class WirelessSecurityController {
  constructor(private readonly wireless: WirelessSecurityService) {}

  // Environments (§77)
  @Get("wireless/environments")
  async listEnvironments(@CurrentUser() user: RequestUser) {
    return this.wireless.listEnvironments(user);
  }

  @Post("wireless/environments")
  async createEnvironment(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(createWirelessEnvironmentSchema, body ?? {});
    return this.wireless.createEnvironment(user, input);
  }

  @Get("wireless/environments/:id")
  async getEnvironment(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.wireless.getEnvironment(user, id);
  }

  @Post("wireless/environments/:id/scan")
  async startScan(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startWirelessScanSchema, body ?? {});
    return this.wireless.startScan(user, id, input);
  }

  // Access points (§77)
  @Get("wireless/access-points")
  async listAccessPoints(@CurrentUser() user: RequestUser, @Query("environmentId") environmentId?: string) {
    return this.wireless.listAccessPoints(user, environmentId);
  }

  @Get("wireless/access-points/:id")
  async getAccessPoint(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.wireless.getAccessPoint(user, id);
  }

  // Sensors (§77 + §12 approval)
  @Get("wireless/sensors")
  async listSensors(@CurrentUser() user: RequestUser) {
    return this.wireless.listSensors(user);
  }

  @Post("wireless/sensors")
  async registerSensor(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerWirelessSensorSchema, body ?? {});
    return this.wireless.registerSensor(user, input);
  }

  @Post("wireless/sensors/:id/approve")
  async approveSensor(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.wireless.approveSensor(user, id);
  }

  // Captures (§77 + §26 approval workflow)
  @Post("wireless/captures")
  async uploadCapture(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(uploadWirelessCaptureSchema, body ?? {});
    return this.wireless.uploadCapture(user, input);
  }

  @Get("wireless/captures/:id")
  async getCapture(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.wireless.getCapture(user, id);
  }

  @Post("wireless/captures/:id/approve")
  async approveCapture(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(approveWirelessCaptureSchema, body ?? {});
    return this.wireless.approveCapture(user, id, input);
  }

  // Approved AP profiles (§43)
  @Get("wireless/environments/:id/approved-profiles")
  async listApprovedProfiles(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.wireless.listApprovedProfiles(user, id);
  }

  @Post("wireless/approved-profiles")
  async createApprovedProfile(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(createApprovedWirelessProfileSchema, body ?? {});
    return this.wireless.createApprovedProfile(user, input);
  }

  // Events + drift (§77)
  @Get("wireless/events")
  async listEvents(@CurrentUser() user: RequestUser, @Query("environmentId") environmentId?: string) {
    return this.wireless.listEvents(user, environmentId);
  }

  @Get("wireless/drift")
  async listDrift(@CurrentUser() user: RequestUser, @Query("environmentId") environmentId?: string) {
    return this.wireless.listDrift(user, environmentId);
  }

  // Lab validation (§65)
  @Post("wireless/lab-validations")
  async requestLabValidation(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(requestWirelessLabValidationSchema, body ?? {});
    return this.wireless.requestLabValidation(user, input);
  }

  // Tool health (§80)
  @Get("wireless/tools")
  async listTools(@CurrentUser() user: RequestUser) {
    return this.wireless.listTools(user);
  }
}
