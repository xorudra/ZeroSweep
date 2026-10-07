import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";
import { z } from "zod";
import { registerCloudAccountSchema, startCloudScanSchema } from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { CloudSecurityService } from "./cloud-security.service";

const resourcesQuerySchema = z.object({
  accountId: z.string().min(1).optional(),
  provider: z.enum(["AWS", "AZURE", "GCP"]).optional(),
  exposure: z.enum(["PUBLIC", "INTERNET_REACHABLE_POSSIBLE", "PRIVATE", "UNKNOWN"]).optional(),
  resourceType: z.string().min(1).max(128).optional(),
  search: z.string().min(1).max(200).optional(),
});

const iamQuerySchema = z.object({
  accountId: z.string().min(1).optional(),
  provider: z.enum(["AWS", "AZURE", "GCP"]).optional(),
});

const driftQuerySchema = z.object({
  accountId: z.string().min(1).optional(),
  kind: z.string().min(1).max(64).optional(),
});

const accountQuerySchema = z.object({
  accountId: z.string().min(1).optional(),
});

const complianceQuerySchema = z.object({
  frameworkKey: z.string().min(1).max(64).optional(),
});

/**
 * Multi-cloud security endpoints (Prompt 14 §87). Registration,
 * validation and scan starts are the only writes; everything else is
 * a tenant-scoped read. There is NO endpoint that creates, modifies
 * or deletes a cloud resource, performs remediation, accepts a
 * credential value, or runs a tool command — assessment is read-only
 * (§7) and credentials are reference names only (§6).
 */
@Controller()
export class CloudSecurityController {
  constructor(private readonly cloud: CloudSecurityService) {}

  // Accounts (§87)
  @Get("cloud/accounts")
  async listAccounts(@CurrentUser() user: RequestUser) {
    return this.cloud.listAccounts(user);
  }

  @Post("cloud/accounts")
  async registerAccount(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerCloudAccountSchema, body ?? {});
    return this.cloud.registerAccount(user, input);
  }

  @Get("cloud/accounts/:id")
  async getAccount(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.cloud.getAccount(user, id);
  }

  @Post("cloud/accounts/:id/validate")
  async validateAccount(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.cloud.validateAccount(user, id);
  }

  @Post("cloud/accounts/:id/scan")
  async scanAccount(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startCloudScanSchema, body ?? {});
    return this.cloud.startAccountScan(user, id, input);
  }

  // Resources (§87)
  @Get("cloud/resources")
  async listResources(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(resourcesQuerySchema, query ?? {});
    return this.cloud.listResources(user, input);
  }

  @Get("cloud/resources/:id")
  async getResource(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.cloud.getResource(user, id);
  }

  // IAM (§87)
  @Get("cloud/iam")
  async listIam(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(iamQuerySchema, query ?? {});
    return this.cloud.listIam(user, input);
  }

  // Exposure (§87)
  @Get("cloud/exposure")
  async listExposure(@CurrentUser() user: RequestUser) {
    return this.cloud.listExposure(user);
  }

  // Drift (§87)
  @Get("cloud/drift")
  async listDrift(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(driftQuerySchema, query ?? {});
    return this.cloud.listDrift(user, input);
  }

  // Graph + risk paths (§85/§87)
  @Get("cloud/graph")
  async getGraph(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(accountQuerySchema, query ?? {});
    return this.cloud.getGraph(user, input);
  }

  @Get("cloud/risk-paths")
  async listRiskPaths(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(accountQuerySchema, query ?? {});
    return this.cloud.listRiskPaths(user, input);
  }

  // Compliance (§84 — Phase 13 framework, cloud benchmarks)
  @Get("cloud/compliance")
  async listCompliance(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(complianceQuerySchema, query ?? {});
    return this.cloud.listCompliance(user, input);
  }
}
