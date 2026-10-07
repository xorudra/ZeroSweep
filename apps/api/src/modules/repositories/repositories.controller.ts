import { Body, Controller, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { z } from "zod";
import {
  createRepositorySchema, createSourceExclusionSchema, startRepositoryScanSchema,
} from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { RepositoriesService } from "./repositories.service";

const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
});

const sbomQuerySchema = z.object({
  format: z.enum(["CYCLONEDX_JSON", "SPDX_TAG_VALUE"]).default("CYCLONEDX_JSON"),
});

const secretLifecycleSchema = z.object({
  lifecycleStatus: z.enum(["OPEN", "ROTATION_REQUIRED", "ROTATED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED"]),
}).strict();

/**
 * Source repository endpoints (Prompt 12 §97). Registration and scan
 * starts are the only writes; everything else is a tenant-scoped read.
 * There is NO endpoint that executes repository content, accepts a tool
 * command, or returns a secret value — secret data is metadata only
 * (§40/§98). Raw snapshot manifest access is OWNER/ADMIN and audited.
 */
@Controller("repositories")
export class RepositoriesController {
  constructor(private readonly repositories: RepositoriesService) {}

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    return this.repositories.listRepositories(user);
  }

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(createRepositorySchema, body ?? {});
    return this.repositories.createRepository(user, input);
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.getRepository(user, id);
  }

  @Post(":id/verify")
  async verify(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.verifyRepository(user, id);
  }

  @Post(":id/scans")
  async startScan(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startRepositoryScanSchema, body ?? {});
    return this.repositories.startScan(user, id, input);
  }

  @Get(":id/snapshots")
  async snapshots(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.listSnapshots(user, id);
  }

  @Get(":id/findings")
  async findings(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    const q = parseOrThrow(paginationSchema, query ?? {});
    return this.repositories.listFindings(user, id, { page: q.page ?? 1, pageSize: q.pageSize ?? 20 });
  }

  @Get(":id/secrets")
  async secrets(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.listSecrets(user, id);
  }

  @Patch(":id/secrets/:secretId")
  async secretLifecycle(@CurrentUser() user: RequestUser, @Param("id") id: string, @Param("secretId") secretId: string, @Body() body: unknown) {
    const input = parseOrThrow(secretLifecycleSchema, body ?? {});
    return this.repositories.updateSecretLifecycle(user, id, secretId, input.lifecycleStatus);
  }

  @Get(":id/dependencies")
  async dependencies(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.listDependencies(user, id);
  }

  @Get(":id/sbom")
  async sbom(@CurrentUser() user: RequestUser, @Param("id") id: string, @Query() query: unknown) {
    const q = parseOrThrow(sbomQuerySchema, query ?? {});
    return this.repositories.getSbom(user, id, q.format);
  }

  @Get(":id/snapshot-manifest")
  async snapshotManifest(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.getSnapshotManifest(user, id);
  }

  @Post(":id/exclusions")
  async createExclusion(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(createSourceExclusionSchema, body ?? {});
    return this.repositories.createExclusion(user, id, input);
  }
}

/** §97: quality-gate verdicts are addressed by SCAN id, not repository. */
@Controller("source-scans")
export class SourceScansController {
  constructor(private readonly repositories: RepositoriesService) {}

  @Get(":id/quality-gate")
  async qualityGate(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.repositories.getQualityGate(user, id);
  }
}
