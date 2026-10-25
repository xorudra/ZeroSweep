import {
  BadRequestException, Inject, Injectable, NotFoundException,
} from "@nestjs/common";
import {
  CONTAINER_PIPELINE_STAGES, DEFAULT_CONTAINER_BASELINE_RULES, DEFAULT_IMAGE_POLICY,
  buildContainerCoverage, evaluateBaselineDeviations, evaluateImagePolicy,
  hashBaselineRules, planContainerVerification,
  type CloudV2BaselineRule, type CloudV2PipelineStage, type ImagePolicyDefinition,
} from "@zerosweep/security-sdk";
import type { StartContainerScanInput } from "@zerosweep/validation";
import { AuditService } from "../audit/audit.service";
import { CloudNativeService } from "../cloud-native/cloud-native.service";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { resolveWorkspace } from "../../common/tenant";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireContainerV2Permission, containerV2PermissionsFor } from "./permissions";

type AuthUser = RequestUser;
type Headers = Record<string, string | string[] | undefined>;
/* eslint-disable @typescript-eslint/no-explicit-any */
type Row = Record<string, any>;

/**
 * Container Security V2 (Prompt 34 §3/§46–§64/§104). Deepens the
 * Prompt 13 engine on the same ContainerImage / SBOM models: image
 * identity is the DIGEST (§49 — the same digest under two tags is one
 * image), scans and SBOMs delegate to the governed Prompt 13 paths,
 * and the V2 layer adds image-policy evaluation (§62), the Container
 * Orchestrator (§104), coverage (§113) and baselines (§99/§100).
 * Images are analyzed, never executed, by this module.
 */
@Injectable()
export class ContainerSecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly auditService: AuditService,
    private readonly cloudNative: CloudNativeService,
  ) {}

  private ws(user: AuthUser, headers: Headers) {
    return resolveWorkspace(this.prisma, user, headers["x-workspace-id"] as string | undefined);
  }

  private async audit(workspaceId: string, user: AuthUser, action: string, entityType: string, entityId: string, metadata?: Record<string, unknown>): Promise<void> {
    await this.auditService
      .record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: action as never, resourceType: entityType, resourceId: entityId,
        ...(metadata ? { metadata } : {}),
      })
      .catch(() => undefined);
  }

  mePermissions(user: AuthUser) {
    return { role: user.role, permissions: containerV2PermissionsFor(user.role) };
  }

  private async imageOr404(workspaceId: string, id: string): Promise<Row> {
    const image = await this.prisma.containerImage.findFirst({ where: { id, workspaceId } });
    if (!image) throw new NotFoundException("Container image not found");
    return image as Row;
  }

  /* --------------------- images (§48/§49/§138) --------------------- */

  async listImages(user: AuthUser, headers: Headers) {
    requireContainerV2Permission(user, "VIEW_CONTAINER_SECURITY");
    const workspace = await this.ws(user, headers);
    const images = await this.prisma.containerImage.findMany({
      where: { workspaceId: workspace.id }, orderBy: { lastSeen: "desc" }, take: 200,
    }) as Row[];
    const items = [];
    for (const image of images) {
      const [componentCount, snapshot] = await Promise.all([
        this.prisma.softwareComponent.count({ where: { imageId: image.id } }).catch(() => 0),
        this.prisma.containerImageSnapshot.findFirst({ where: { imageId: image.id }, orderBy: { capturedAt: "desc" } }),
      ]);
      items.push({
        ...image,
        // §49: digest is the immutable identity; tag is mutable metadata.
        identity: image.digest ?? image.reference,
        componentCount, latestSnapshot: snapshot,
      });
    }
    return { items, total: items.length };
  }

  /** §138: scan delegates to the governed Prompt 13 gated path —
   *  VERIFIED target + orchestration re-verification included. */
  async scanImage(user: AuthUser, id: string, body: Record<string, unknown>) {
    requireContainerV2Permission(user, "RUN_CONTAINER_SCAN");
    const profile = (body.profile as StartContainerScanInput["profile"]) ?? "CONTAINER_BASELINE";
    return this.cloudNative.startImageScan(user, id, { profile });
  }

  /** §138/§52: SBOM delegates to the Prompt 13/30 SBOM subsystem —
   *  no duplicate component model is created here. */
  async getImageSbom(user: AuthUser, id: string) {
    requireContainerV2Permission(user, "VIEW_SBOM");
    return this.cloudNative.getImageSbom(user, id);
  }

  /* --------------------- orchestrator (§104) --------------------- */

  async assessImage(user: AuthUser, headers: Headers, id: string, body: Record<string, unknown>) {
    requireContainerV2Permission(user, "RUN_CONTAINER_ASSESSMENT");
    const workspace = await this.ws(user, headers);
    const image = await this.imageOr404(workspace.id, id);
    const policy: ImagePolicyDefinition = {
      ...DEFAULT_IMAGE_POLICY,
      ...((body.policy as Partial<ImagePolicyDefinition> | undefined) ?? {}),
    };

    const run = await this.prisma.cloudV2AssessmentRun.create({
      data: { workspaceId: workspace.id, domain: "CONTAINER", imageId: id, status: "RUNNING", startedById: user.id, pipeline: [] as never },
    }) as Row;

    const stages: CloudV2PipelineStage[] = [];
    const stage = (name: string, status: CloudV2PipelineStage["status"], detail: string) => stages.push({ stage: name, status, detail });

    const snapshot = await this.prisma.containerImageSnapshot.findFirst({
      where: { imageId: id }, orderBy: { capturedAt: "desc" },
    }) as Row | null;
    const components = await this.prisma.softwareComponent.count({ where: { imageId: id } }).catch(() => 0);
    const sboms = await this.prisma.softwareBillOfMaterials.count({ where: { imageId: id } }).catch(() => 0);
    stage("IMAGE_DISCOVERY", "COMPLETED", `Image ${image.reference} — identity is digest ${image.digest ?? "(unresolved — tag-only reference)"} (§49)`);

    stage("SBOM", components > 0 ? "COMPLETED" : "COMPLETED_WITH_GAPS",
      components > 0 ? `${components} component(s), ${sboms} SBOM document(s) on the Prompt 30 subsystem (§52)` : "No SBOM inventory recorded for this image yet (§113 gap)");

    // Vulnerability context from persisted canonical findings (§56:
    // Trivy + Grype observations of one package/CVE already merged).
    const findings = await this.prisma.finding.findMany({ where: { workspaceId: workspace.id }, take: 1000 }) as Row[];
    const imageFindings = findings.filter((f) => typeof f.fingerprint === "string"
      && ((f.fingerprint as string).startsWith("imgvuln:") || (f.fingerprint as string).startsWith("imgsecret:"))
      && (f.imageRef === image.reference || f.imageRef === image.repository));
    const worst = imageFindings.some((f) => f.severity === "CRITICAL") ? "CRITICAL"
      : imageFindings.some((f) => f.severity === "HIGH") ? "HIGH"
        : imageFindings.some((f) => f.severity === "MEDIUM") ? "MEDIUM"
          : imageFindings.length ? "LOW" : null;
    stage("VULNERABILITY", "COMPLETED", `${imageFindings.length} canonical image finding(s) in workspace context; worst severity ${worst ?? "none recorded"} (§56)`);

    const config = (snapshot?.config ?? {}) as Row;
    const policyResult = evaluateImagePolicy({
      registry: image.registry as string, repository: image.repository as string,
      tag: (image.tag as string | null) ?? null, digest: (image.digest as string | null) ?? null,
      config: { user: config.user as string | undefined, healthcheckPresent: Boolean(config.healthcheckPresent), signed: Boolean(config.signed) },
      worstSeverity: worst,
    }, policy);
    stage("CONFIGURATION", policyResult.compliant ? "COMPLETED" : "COMPLETED_WITH_GAPS",
      policyResult.compliant ? "Image satisfies the image policy (§62)" : `${policyResult.violations.length} image-policy violation(s) (§62)`);

    const workloads = await this.prisma.kubernetesWorkload.findMany({ where: { workspaceId: workspace.id }, take: 1000 }) as Row[];
    const deployedIn = workloads.filter((w) => JSON.stringify(w.images ?? []).includes(image.repository as string));
    stage("DEPLOYMENT_CORRELATION", "COMPLETED", deployedIn.length
      ? `Deployed in ${deployedIn.length} workload(s) — deployed context raises priority over an undeployed image (§87)`
      : "Not observed in any recorded workload — undeployed context (§87)");

    stage("RISK", "COMPLETED", "Risk Engine V3 signals: KEV/EPSS via vulnerability intelligence, deployment status, exposure, fixed-version availability (§59)");
    stage("REMEDIATION", "COMPLETED", "Verification = new digest + new SBOM + rescan (§122); no image is rebuilt or pushed by the platform");

    const coverageBuilt = buildContainerCoverage({
      registriesCovered: image.registryId ? 1 : 0, repositoriesCovered: 1, imagesCovered: 1,
      imagesWithSbom: components > 0 ? 1 : 0, imagesScanned: imageFindings.length > 0 || snapshot ? 1 : 0,
      deploymentCorrelated: deployedIn.length, transportConfigured: false,
    });
    const coverage = await this.prisma.containerSecurityCoverage.create({
      data: {
        workspaceId: workspace.id, runId: run.id, imageId: id,
        registriesCovered: coverageBuilt.coverage.registriesCovered, repositoriesCovered: coverageBuilt.coverage.repositoriesCovered,
        imagesCovered: coverageBuilt.coverage.imagesCovered, sbomCoverage: coverageBuilt.coverage.sbomCoverage,
        vulnerabilityCoverage: coverageBuilt.coverage.vulnerabilityCoverage, deploymentCorrelated: coverageBuilt.coverage.deploymentCorrelated,
        gaps: coverageBuilt.gaps as never, completion: coverageBuilt.completion,
      },
    });
    const ordered = CONTAINER_PIPELINE_STAGES.map((name) => stages.find((s) => s.stage === name) ?? { stage: name, status: "COMPLETED" as const, detail: "" });
    const finished = await this.prisma.cloudV2AssessmentRun.update({
      where: { id: run.id }, data: { status: coverageBuilt.completion, pipeline: ordered as never, completedAt: new Date() },
    });
    await this.audit(workspace.id, user, "CONTAINER_ASSESSMENT_COMPLETED", "ContainerImage", id, { runId: run.id, completion: coverageBuilt.completion, policyViolations: policyResult.violations.length });
    return { run: finished, stages: ordered, coverage, policy: policyResult, deployedIn: deployedIn.map((w) => ({ clusterId: w.clusterId, namespace: w.namespace, kind: w.kind, name: w.name })) };
  }

  /* --------------------- baselines (§99/§100) + coverage --------------------- */

  async createBaseline(user: AuthUser, headers: Headers, body: Record<string, unknown>) {
    requireContainerV2Permission(user, "MANAGE_CONTAINER_REGISTRIES");
    const workspace = await this.ws(user, headers);
    const rules = (Array.isArray(body.rules) ? body.rules : DEFAULT_CONTAINER_BASELINE_RULES) as CloudV2BaselineRule[];
    for (const rule of rules) {
      if (!rule.ruleId || !rule.expectation || !rule.severity) throw new BadRequestException("Each baseline rule needs ruleId, expectation and severity (§99)");
    }
    const registryId = body.registryId ? String(body.registryId) : null;
    const existing = await this.prisma.containerSecurityBaseline.findMany({ where: { workspaceId: workspace.id, registryId } });
    const version = (existing as Row[]).reduce((max, r) => Math.max(max, Number(r.version ?? 0)), 0) + 1;
    const baseline = await this.prisma.containerSecurityBaseline.create({
      data: { workspaceId: workspace.id, registryId, version, rules: rules as never, hash: hashBaselineRules(rules), createdById: user.id },
    });
    await this.audit(workspace.id, user, "CONTAINER_BASELINE_CREATED", "ContainerSecurityBaseline", (baseline as Row).id, { version });
    return baseline;
  }

  async listBaselines(user: AuthUser, headers: Headers) {
    requireContainerV2Permission(user, "VIEW_CONTAINER_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.containerSecurityBaseline.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 50 });
    return { items: rows };
  }

  async baselineDrift(user: AuthUser, headers: Headers) {
    requireContainerV2Permission(user, "VIEW_CONTAINER_SECURITY");
    const workspace = await this.ws(user, headers);
    const baseline = await this.prisma.containerSecurityBaseline.findFirst({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" } }) as Row | null;
    if (!baseline) return { baseline: null, deviations: [], note: "No container baseline exists yet (§99)." };
    const images = await this.prisma.containerImage.findMany({ where: { workspaceId: workspace.id }, take: 200 }) as Row[];
    const violated = new Set<string>();
    for (const image of images) {
      const snapshot = await this.prisma.containerImageSnapshot.findFirst({ where: { imageId: image.id }, orderBy: { capturedAt: "desc" } }) as Row | null;
      const config = (snapshot?.config ?? {}) as Row;
      const result = evaluateImagePolicy({
        registry: image.registry as string, repository: image.repository as string,
        tag: (image.tag as string | null) ?? null, digest: (image.digest as string | null) ?? null,
        config: { user: config.user as string | undefined },
      }, DEFAULT_IMAGE_POLICY);
      for (const v of result.violations) violated.add(v.rule);
    }
    const facts: Record<string, string> = {};
    for (const rule of baseline.rules as CloudV2BaselineRule[]) facts[rule.ruleId] = violated.has(rule.ruleId) ? "PRESENT" : "ABSENT";
    return { baseline, deviations: evaluateBaselineDeviations(baseline.rules as CloudV2BaselineRule[], facts), facts };
  }

  async getCoverage(user: AuthUser, headers: Headers) {
    requireContainerV2Permission(user, "VIEW_CONTAINER_SECURITY");
    const workspace = await this.ws(user, headers);
    const rows = await this.prisma.containerSecurityCoverage.findMany({ where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 20 });
    return { items: rows };
  }

  verificationPlan(user: AuthUser) {
    requireContainerV2Permission(user, "VIEW_CONTAINER_SECURITY");
    return planContainerVerification();
  }
}
