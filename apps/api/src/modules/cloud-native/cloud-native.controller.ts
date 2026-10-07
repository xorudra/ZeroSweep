import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";
import { z } from "zod";
import {
  createContainerRegistrySchema, createKubernetesClusterSchema, ingestRuntimeEventSchema,
  registerContainerImageSchema, startContainerScanSchema, startKubernetesScanSchema,
} from "@dsrclone/validation";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { CloudNativeService } from "./cloud-native.service";

const workloadsQuerySchema = z.object({
  clusterId: z.string().min(1).optional(),
  namespace: z.string().min(1).max(253).optional(),
});

const complianceQuerySchema = z.object({
  frameworkKey: z.string().min(1).max(64).optional(),
});

const runtimeQuerySchema = z.object({
  namespace: z.string().min(1).max(253).optional(),
});

/**
 * Container / Kubernetes endpoints (Prompt 13 §91). Registration and
 * scan starts are the only writes besides trusted runtime-event
 * ingestion; everything else is a tenant-scoped read. There is NO
 * endpoint that runs an image, applies a manifest, returns a secret
 * value, or accepts a tool command — credentials are reference names
 * only (§6/§33/§36).
 */
@Controller()
export class CloudNativeController {
  constructor(private readonly cloud: CloudNativeService) {}

  // Container images (§91)
  @Get("container-images")
  async listImages(@CurrentUser() user: RequestUser) {
    return this.cloud.listImages(user);
  }

  @Post("container-images")
  async registerImage(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(registerContainerImageSchema, body ?? {});
    return this.cloud.registerImage(user, input);
  }

  @Get("container-images/:id")
  async getImage(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.cloud.getImage(user, id);
  }

  @Post("container-images/:id/scan")
  async scanImage(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startContainerScanSchema, body ?? {});
    return this.cloud.startImageScan(user, id, input);
  }

  @Get("container-images/:id/sbom")
  async imageSbom(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.cloud.getImageSbom(user, id);
  }

  // Registries (§91)
  @Get("container-registries")
  async listRegistries(@CurrentUser() user: RequestUser) {
    return this.cloud.listRegistries(user);
  }

  @Post("container-registries")
  async createRegistry(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(createContainerRegistrySchema, body ?? {});
    return this.cloud.createRegistry(user, input);
  }

  // Kubernetes (§91)
  @Get("kubernetes/clusters")
  async listClusters(@CurrentUser() user: RequestUser) {
    return this.cloud.listClusters(user);
  }

  @Post("kubernetes/clusters")
  async createCluster(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(createKubernetesClusterSchema, body ?? {});
    return this.cloud.createCluster(user, input);
  }

  @Get("kubernetes/clusters/:id")
  async getCluster(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.cloud.getCluster(user, id);
  }

  @Post("kubernetes/clusters/:id/scan")
  async scanCluster(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const input = parseOrThrow(startKubernetesScanSchema, body ?? {});
    return this.cloud.startClusterScan(user, id, input);
  }

  @Get("kubernetes/workloads")
  async listWorkloads(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(workloadsQuerySchema, query ?? {});
    return this.cloud.listWorkloads(user, input);
  }

  // Compliance (§91)
  @Get("compliance/assessments")
  async compliance(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(complianceQuerySchema, query ?? {});
    return this.cloud.listComplianceAssessments(user, input);
  }

  // Runtime events (§91)
  @Get("runtime-events")
  async runtimeEvents(@CurrentUser() user: RequestUser, @Query() query: unknown) {
    const input = parseOrThrow(runtimeQuerySchema, query ?? {});
    return this.cloud.listRuntimeEvents(user, input);
  }

  @Post("runtime-events")
  async ingestRuntimeEvent(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const input = parseOrThrow(ingestRuntimeEventSchema, body ?? {});
    return this.cloud.ingestRuntimeEvent(user, input);
  }
}
