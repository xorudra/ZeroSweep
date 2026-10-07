import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  FalcoConnector, buildCycloneDxSbom, parseImageReference, validateRegistryUrl,
} from "@dsrclone/security-sdk";
import type {
  CreateContainerRegistryInput, CreateKubernetesClusterInput, IngestRuntimeEventInput,
  RegisterContainerImageInput, StartContainerScanInput, StartKubernetesScanInput,
} from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService, hostOf } from "../orchestration/orchestration.service";
import { requireCloudPermission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

/**
 * Container, Docker & Kubernetes security API (Prompt 13 §91).
 *
 * Discipline carried through every method:
 * - Images are analyzed STATICALLY (§9): registration records a
 *   reference; nothing here pulls, runs or executes an image.
 * - Credentials exist ONLY as secret-reference names (§6/§33) — no
 *   kubeconfig, token or registry password is accepted, stored or
 *   returned by any endpoint.
 * - Kubernetes secret VALUES are never retrieved (§36): cluster views
 *   expose counts and metadata only.
 * - Compliance assessments are control evidence (§55/§88) — this API
 *   never labels a score as certification.
 * - Scans start through the ordinary gated orchestration path
 *   (VERIFIED target + APPROVED assessment + scope), never directly.
 */
@Injectable()
export class CloudNativeService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  // ── Container images (§84/§85/§91) ─────────────────────────────

  async listImages(user: RequestUser) {
    requireCloudPermission(user, "VIEW_CONTAINER_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.containerImage.findMany({
      where: { workspaceId: workspace.id }, orderBy: { lastSeen: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const findings = await this.prisma.finding.count({ where: { imageRef: (r.reference as string) ?? undefined, workspaceId: workspace.id } }).catch(() => 0);
      items.push({
        id: r.id, reference: r.reference, registry: r.registry, repository: r.repository,
        tag: r.tag ?? null, digest: r.digest ?? null, platform: r.platform ?? null,
        source: r.source, firstSeen: r.firstSeen, lastSeen: r.lastSeen, findings,
      });
    }
    return { items };
  }

  async registerImage(user: RequestUser, input: RegisterContainerImageInput) {
    requireCloudPermission(user, "MANAGE_REGISTRIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    let ref: ReturnType<typeof parseImageReference>;
    try {
      ref = parseImageReference(input.image);
    } catch (err) {
      throw new BadRequestException(err instanceof Error ? err.message : "invalid image reference");
    }
    const existing = await this.prisma.containerImage.findFirst({
      where: { workspaceId: workspace.id, registry: ref.registry, repository: ref.repository, digest: ref.digest ?? null },
    });
    if (existing) return { id: (existing as Row).id, reference: input.image, alreadyRegistered: true };
    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.image, type: "CONTAINER_IMAGE",
        value: input.image, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const image = await this.prisma.containerImage.create({
      data: {
        workspaceId: workspace.id, targetId: target.id, reference: input.image,
        registry: ref.registry, repository: ref.repository, tag: ref.tag, digest: ref.digest,
        source: input.source ?? "MANUAL",
        ...(input.registryId ? { registryId: input.registryId } : {}),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "CONTAINER_IMAGE_REGISTERED", resourceType: "ContainerImage", resourceId: image.id,
      metadata: { reference: input.image },
    });
    return { id: image.id, targetId: target.id, reference: input.image, verified: false };
  }

  private async loadImage(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const image = await this.prisma.containerImage.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!image) throw new NotFoundException("Container image not found");
    return { workspace, image: image as unknown as Row & { targetId: string | null; reference: string } };
  }

  async getImage(user: RequestUser, id: string) {
    requireCloudPermission(user, "VIEW_CONTAINER_SECURITY");
    const { workspace, image } = await this.loadImage(user, id);
    const snapshots = await this.prisma.containerImageSnapshot.findMany({
      where: { imageId: id }, orderBy: { capturedAt: "desc" }, take: 20,
    });
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId: workspace.id, imageRef: image.reference }, orderBy: { createdAt: "desc" }, take: 100,
    });
    const components = await this.prisma.softwareComponent.count({ where: { imageId: id } }).catch(() => 0);
    return {
      ...image,
      snapshots: (snapshots as unknown as Row[]).map((s) => ({
        id: s.id, digest: s.digest, previousDigest: s.previousDigest ?? null,
        drift: s.drift ?? false, scanId: s.scanId ?? null, capturedAt: s.capturedAt,
      })),
      findings: (findings as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, cve: f.cve ?? null,
        origin: f.origin ?? null, controlId: f.controlId ?? null, status: f.status,
      })),
      componentCount: components,
    };
  }

  /** POST /container-images/:id/scan (§91): records the engagement
   *  approval for this image+profile, then starts through the gated
   *  orchestration path — which re-verifies independently. The target
   *  must be VERIFIED first (registration review), exactly like every
   *  other target kind (§4 discipline). */
  async startImageScan(user: RequestUser, id: string, input: StartContainerScanInput) {
    requireCloudPermission(user, "RUN_CONTAINER_SCAN");
    const profile = input.profile ?? "CONTAINER_BASELINE";
    const { workspace, image } = await this.loadImage(user, id);
    if (!image.targetId) throw new BadRequestException("image has no target");
    const target = await this.prisma.target.findUnique({ where: { id: image.targetId } });
    if (!target?.verified) throw new BadRequestException("Image target is not VERIFIED — verify the image registration before scanning");
    const started = await this.startGatedScan(user, workspace.id, target as unknown as Row & { id: string; value: string }, image.reference, profile, "ContainerImage", image.id, "CONTAINER_SCAN_STARTED");
    return { imageId: image.id, ...started };
  }

  /** GET /container-images/:id/sbom (§85): the image SBOM document is
   *  built on demand from the persisted component inventory (§12) and
   *  its reference + checksum recorded — the document itself is an
   *  artifact, never a database blob. */
  async getImageSbom(user: RequestUser, id: string) {
    requireCloudPermission(user, "VIEW_CONTAINER_SECURITY");
    const { workspace, image } = await this.loadImage(user, id);
    const rows = await this.prisma.softwareComponent.findMany({ where: { imageId: id }, take: 5000 });
    if ((rows as unknown[]).length === 0) {
      throw new NotFoundException("No SBOM inventory for this image yet — run an SBOM profile scan first");
    }
    const components = (rows as unknown as Row[]).map((r) => ({
      name: r.name as string, version: (r.version as string) ?? undefined, ecosystem: r.ecosystem as never,
      purl: r.purl as string, sourceManifest: r.sourceManifest as string, scope: r.scope as never,
      dependencyScope: r.dependencyScope as never, licenses: r.licenses as string[],
      ...(r.supplier ? { supplier: r.supplier as string } : {}),
    }));
    const { sbom } = buildCycloneDxSbom(components, {
      snapshotHash: (image.digest as string | null) ?? image.reference, repositoryName: image.reference, timestamp: new Date().toISOString(),
    });
    const existing = await this.prisma.softwareBillOfMaterials.findFirst({ where: { imageId: id, format: "CYCLONEDX_JSON" } });
    if (existing) {
      await this.prisma.softwareBillOfMaterials.update({ where: { id: (existing as Row).id }, data: { checksum: sbom.checksum, componentCount: sbom.componentCount, artifactRef: `sbom://image/${id}/${sbom.checksum}` } as never });
    } else {
      await this.prisma.softwareBillOfMaterials.create({
        data: {
          imageId: id, format: "CYCLONEDX_JSON", specVersion: sbom.specVersion,
          checksum: sbom.checksum, artifactRef: `sbom://image/${id}/${sbom.checksum}`, componentCount: sbom.componentCount,
        } as never,
      });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SBOM_GENERATED", resourceType: "ContainerImage", resourceId: id,
      metadata: { format: "CYCLONEDX_JSON", components: sbom.componentCount },
    });
    return { imageId: id, format: sbom.format, specVersion: sbom.specVersion, checksum: sbom.checksum, componentCount: sbom.componentCount, document: sbom.document };
  }

  // ── Registries (§6/§91) ────────────────────────────────────────

  async listRegistries(user: RequestUser) {
    requireCloudPermission(user, "VIEW_CONTAINER_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.containerRegistry.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100 });
    return {
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, name: r.name, url: r.url, provider: r.provider,
        // Reference NAME only — the secret itself is never stored (§6).
        credentialReference: r.credentialReference ?? null, createdAt: r.createdAt,
      })),
    };
  }

  async createRegistry(user: RequestUser, input: CreateContainerRegistryInput) {
    requireCloudPermission(user, "MANAGE_REGISTRIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const verdict = validateRegistryUrl(input.url);
    if (!verdict.allowed) throw new BadRequestException(`Registry URL refused: ${verdict.reason}`);
    const registry = await this.prisma.containerRegistry.create({
      data: {
        workspaceId: workspace.id, name: input.name, url: input.url,
        ...(input.provider ? { provider: input.provider } : {}),
        credentialReference: input.credentialReference,
        createdBy: user.id,
      },
    });
    return { id: registry.id, name: registry.name, url: registry.url };
  }

  // ── Kubernetes (§83/§86/§87/§91) ───────────────────────────────

  async listClusters(user: RequestUser) {
    requireCloudPermission(user, "VIEW_KUBERNETES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.kubernetesCluster.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 100 });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const workloads = await this.prisma.kubernetesWorkload.count({ where: { clusterId: r.id } }).catch(() => 0);
      items.push({
        id: r.id, name: r.name, provider: r.provider ?? null, version: r.version ?? null,
        // Reference only — no endpoint URL, no credential value (§33).
        apiServerReference: r.apiServerReference, credentialReference: r.credentialReference ?? null,
        lastAssessmentAt: r.lastAssessmentAt ?? null,
        workloads,
      });
    }
    return { items };
  }

  async createCluster(user: RequestUser, input: CreateKubernetesClusterInput) {
    requireCloudPermission(user, "MANAGE_KUBERNETES_CONNECTIONS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.name, type: "KUBERNETES_CLUSTER",
        value: input.name, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const cluster = await this.prisma.kubernetesCluster.create({
      data: {
        workspaceId: workspace.id, targetId: target.id, name: input.name,
        apiServerReference: input.apiServerReference, credentialReference: input.credentialReference,
        ...(input.provider ? { provider: input.provider } : {}),
        version: input.version,
        ...(input.environment ? { environment: input.environment } : {}),
        ...(input.criticality ? { criticality: input.criticality } : {}),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "KUBERNETES_CLUSTER_REGISTERED", resourceType: "KubernetesCluster", resourceId: cluster.id,
      metadata: { name: input.name },
    });
    return { id: cluster.id, targetId: target.id, name: cluster.name, verified: false };
  }

  private async loadCluster(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const cluster = await this.prisma.kubernetesCluster.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!cluster) throw new NotFoundException("Kubernetes cluster not found");
    return { workspace, cluster: cluster as unknown as Row & { targetId: string | null; name: string } };
  }

  async getCluster(user: RequestUser, id: string) {
    requireCloudPermission(user, "VIEW_KUBERNETES");
    const { cluster } = await this.loadCluster(user, id);
    const workloads = await this.prisma.kubernetesWorkload.findMany({
      where: { clusterId: id }, orderBy: [{ namespace: "asc" }, { name: "asc" }], take: 500,
    });
    return {
      ...cluster,
      credentialReference: cluster.credentialReference ?? null,
      secretValuesExposed: false, // §36: values are never retrieved, by design
      workloads: (workloads as unknown as Row[]).map((w) => ({
        id: w.id, kind: w.kind, namespace: w.namespace, name: w.name,
        images: w.images, exposure: w.exposure, serviceAccount: w.serviceAccount ?? null,
      })),
    };
  }

  async startClusterScan(user: RequestUser, id: string, input: StartKubernetesScanInput) {
    requireCloudPermission(user, "RUN_KUBERNETES_SCAN");
    const profile = input.profile ?? "KUBERNETES_BASELINE";
    const { workspace, cluster } = await this.loadCluster(user, id);
    if (!cluster.targetId) throw new BadRequestException("cluster has no target");
    const target = await this.prisma.target.findUnique({ where: { id: cluster.targetId } });
    if (!target?.verified) throw new BadRequestException("Cluster target is not VERIFIED — verify the cluster registration before scanning");
    const started = await this.startGatedScan(user, workspace.id, target as unknown as Row & { id: string; value: string }, cluster.name, profile, "KubernetesCluster", cluster.id, "KUBERNETES_SCAN_STARTED");
    return { clusterId: cluster.id, ...started };
  }

  async listWorkloads(user: RequestUser, query: { clusterId?: string; namespace?: string }) {
    requireCloudPermission(user, "VIEW_KUBERNETES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.kubernetesWorkload.findMany({
      where: {
        workspaceId: workspace.id,
        ...(query.clusterId ? { clusterId: query.clusterId } : {}),
        ...(query.namespace ? { namespace: query.namespace } : {}),
      },
      orderBy: [{ namespace: "asc" }, { name: "asc" }], take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((w) => ({
        id: w.id, clusterId: w.clusterId, kind: w.kind, namespace: w.namespace, name: w.name,
        replicas: w.replicas ?? null, serviceAccount: w.serviceAccount ?? null,
        images: w.images, securityContext: w.securityContext, exposure: w.exposure, lastSeen: w.lastSeen,
      })),
    };
  }

  // ── Compliance (§88/§91) ───────────────────────────────────────

  async listComplianceAssessments(user: RequestUser, query: { frameworkKey?: string }) {
    requireCloudPermission(user, "VIEW_KUBERNETES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.controlAssessment.findMany({
      where: { workspaceId: workspace.id, ...(query.frameworkKey ? { frameworkKey: query.frameworkKey } : {}) },
      orderBy: { assessedAt: "desc" }, take: 500,
    });
    const byStatus: Record<string, number> = {};
    for (const r of rows as unknown as Row[]) byStatus[r.status as string] = (byStatus[r.status as string] ?? 0) + 1;
    return {
      // §88: posture evidence, NEVER a certification claim.
      disclaimer: "Control assessments are posture evidence from governed checks; they are not a compliance certification.",
      byStatus,
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, frameworkKey: r.frameworkKey, controlId: r.controlId, subjectRef: r.subjectRef,
        status: r.status, evidence: r.evidence ?? null, assessedAt: r.assessedAt, scanId: r.scanId ?? null,
      })),
    };
  }

  // ── Runtime events (§59/§89/§91) ───────────────────────────────

  async listRuntimeEvents(user: RequestUser, query: { namespace?: string }) {
    requireCloudPermission(user, "VIEW_RUNTIME_EVENTS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.runtimeSecurityEvent.findMany({
      where: { workspaceId: workspace.id, ...(query.namespace ? { namespace: query.namespace } : {}) },
      orderBy: { eventTime: "desc" }, take: 200,
    });
    return {
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, clusterName: r.clusterName ?? null, node: r.node ?? null, namespace: r.namespace ?? null,
        pod: r.pod ?? null, container: r.container ?? null, rule: r.rule, priority: r.priority,
        eventTime: r.eventTime, source: r.source, ingestedAt: r.ingestedAt,
      })),
    };
  }

  /** POST /runtime-events (§61/§91): the trusted sensor ingestion
   *  path. Payloads pass through the Falco connector's validation +
   *  sanitization (§60) before anything persists; arbitrary rule
   *  UPLOADS are not accepted here — the payload names an existing
   *  sensor rule, it cannot define one. */
  async ingestRuntimeEvent(user: RequestUser, input: IngestRuntimeEventInput) {
    requireCloudPermission(user, "MANAGE_CLOUD_NATIVE_POLICIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const connector = new FalcoConnector();
    const line = JSON.stringify({
      rule: input.rule, priority: input.priority, time: input.time,
      output_fields: {
        ...(input.outputFields ?? {}),
        ...(input.namespace ? { "k8s.ns.name": input.namespace } : {}),
        ...(input.pod ? { "k8s.pod.name": input.pod } : {}),
        ...(input.container ? { "container.name": input.container } : {}),
        ...(input.node ? { node: input.node } : {}),
      },
    });
    const { events } = connector.ingest(line, { ...(input.clusterName ? { clusterRef: input.clusterName } : {}) });
    if (events.length === 0) throw new BadRequestException("runtime event failed validation and was not stored");
    const e = events[0]!;
    const row = await this.prisma.runtimeSecurityEvent.create({
      data: {
        workspaceId: workspace.id, clusterName: e.clusterName, node: e.node, namespace: e.namespace,
        pod: e.pod, container: e.container, rule: e.rule, priority: e.priority,
        eventTime: new Date(e.eventTime), metadata: e.metadata as never, source: e.source,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "RUNTIME_EVENT_INGESTED", resourceType: "RuntimeSecurityEvent", resourceId: row.id,
      metadata: { rule: e.rule },
    });
    return { id: row.id, rule: e.rule, ingested: true };
  }

  // ── Shared gated scan start (mirrors Prompt 12 §97 discipline) ──

  private async startGatedScan(
    user: RequestUser,
    workspaceId: string,
    target: Row & { id: string; value: string },
    scopeHost: string,
    profile: string,
    resourceType: string,
    resourceId: string,
    auditAction: string,
  ) {
    let scope = await this.prisma.scope.findFirst({ where: { targetId: target.id } });
    if (!scope) {
      scope = await this.prisma.scope.create({
        data: {
          workspaceId, targetId: target.id, name: `${scopeHost} cloud-native scope`,
          rules: { includeHosts: [hostOf(target.value)], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] } as never,
        },
      });
    }
    let assessment = await this.prisma.assessment.findFirst({
      where: { targetId: target.id, profile: profile as never, status: "APPROVED" },
      orderBy: { createdAt: "desc" },
    });
    if (!assessment) {
      assessment = await this.prisma.assessment.create({
        data: {
          workspaceId, targetId: target.id, scopeId: (scope as Row).id,
          name: `${scopeHost} — ${profile}`, profile: profile as never,
          status: "APPROVED", createdBy: user.id, approvedBy: user.id,
        },
      });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: auditAction, resourceType, resourceId,
      metadata: { profile, assessmentId: (assessment as Row).id },
    });
    const started = await this.orchestration.startScan(user, (assessment as Row).id);
    return { assessmentId: (assessment as Row).id, ...started };
  }
}
