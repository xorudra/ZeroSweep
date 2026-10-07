import { Body, Controller, Get, Param, Post } from "@nestjs/common";
import {
  approveBinaryDebugSessionSchema, createBinaryDebugSessionSchema, createBinaryDiffSchema,
  registerBinaryArtifactSchema, startBinaryScanSchema,
} from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { BinarySecurityService } from "./binary-security.service";

/**
 * Binary security endpoints (Prompt 18 §92). Registration, gated
 * scan starts, diff creation and governed debug-session requests are
 * the only writes; everything else is a tenant-scoped read. There is
 * NO endpoint that executes, loads, debugs or emulates a binary,
 * accepts a raw shell/GDB/Python/Ghidra/r2 command, or returns a raw
 * secret value — those capabilities do not exist in DSRclone
 * (§93/§114/§123).
 */
@Controller()
export class BinarySecurityController {
  constructor(private readonly binary: BinarySecurityService) {}

  // Artifacts (§92)
  @Get("binaries")
  async listArtifacts(@CurrentUser() user: RequestUser) {
    return this.binary.listArtifacts(user);
  }

  @Post("binaries")
  async registerArtifact(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerBinaryArtifactSchema, body ?? {});
    return this.binary.registerArtifact(user, input);
  }

  @Get("binaries/:id")
  async getArtifact(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.binary.getArtifact(user, id);
  }

  @Post("binaries/:id/scan")
  async startScan(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startBinaryScanSchema, body ?? {});
    return this.binary.startScan(user, id, input);
  }

  @Get("binaries/:id/functions")
  async listFunctions(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.binary.listFunctions(user, id);
  }

  @Get("binaries/:id/dependencies")
  async listDependencies(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.binary.listDependencies(user, id);
  }

  @Get("binaries/:id/hardening")
  async getHardening(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.binary.getHardening(user, id);
  }

  // Diffs (§92)
  @Post("binary-diffs")
  async createDiff(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(createBinaryDiffSchema, body ?? {});
    return this.binary.createDiff(user, input);
  }

  @Get("binary-diffs/:id")
  async getDiff(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.binary.getDiff(user, id);
  }

  // Debug sessions (§92)
  @Post("binaries/:id/debug-sessions")
  async createDebugSession(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(createBinaryDebugSessionSchema, body ?? {});
    return this.binary.createDebugSession(user, id, input);
  }

  @Post("binary-debug-sessions/:id/approve")
  async approveDebugSession(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(approveBinaryDebugSessionSchema, body ?? {});
    return this.binary.approveDebugSession(user, id, input);
  }

  @Get("binary-debug-sessions/:id")
  async getDebugSession(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.binary.getDebugSession(user, id);
  }

  // Tool health (§95)
  @Get("binary/tools")
  async listTools(@CurrentUser() user: RequestUser) {
    return this.binary.listTools(user);
  }
}
