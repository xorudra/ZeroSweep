import { Body, Controller, Get, Inject, Param, Patch, Post, Query } from "@nestjs/common";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import {
  createBaselineSchema, createGatePolicySchema, createRepositoryLinkSchema, updateRepositoryPolicySchema,
} from "./dto/schemas";
import { RepositoriesIntegrationService } from "./repositories/repositories-integration.service";
import { QualityGatesService } from "./quality-gates/quality-gates.service";
import { CicdService } from "./cicd/cicd.service";
import { WebhooksService } from "./webhooks/webhooks.service";
import { requireIntegrationPermission } from "./permissions";
import { NotFoundException } from "@nestjs/common";

type Row = Record<string, unknown>;

/**
 * DevSecOps API (Prompt 24 §107): repository security posture, PR/MR
 * assessments, pipeline runs, quality gates and baselines.
 */
@Controller("devsecops")
export class DevSecopsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly repositories: RepositoriesIntegrationService,
    private readonly gates: QualityGatesService,
    private readonly cicd: CicdService,
    private readonly webhooks: WebhooksService,
  ) {}

  @Get("repositories")
  async repositories_(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const links = await this.repositories.listLinks(user, ws.id);
    const repos = await this.prisma.sourceRepository.findMany({ where: { workspaceId: ws.id } });
    const byId = new Map((repos as Row[]).map((r) => [r.id as string, r]));
    const runs = await this.prisma.securityPipelineRun.findMany({
      where: { workspaceId: ws.id }, orderBy: { startedAt: "desc" }, take: 20,
    });
    const assessments = await this.prisma.pullRequestSecurityAssessment.findMany({
      where: { workspaceId: ws.id }, orderBy: { createdAt: "desc" }, take: 20,
    });
    return {
      repositories: (links as Row[]).map((link) => ({
        link,
        repository: byId.get(link.sourceRepositoryId as string) ?? null,
      })),
      recentPipelineRuns: runs,
      recentPullRequestAssessments: assessments,
    };
  }

  @Post("repositories/links")
  async createLink(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.repositories.createLink(user, ws.id, parseOrThrow(createRepositoryLinkSchema, body ?? {}));
  }

  @Get("repositories/:id")
  async repositoryDetail(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const repository = await this.prisma.sourceRepository.findFirst({ where: { id, workspaceId: ws.id } });
    if (!repository) throw new NotFoundException("Repository not found");
    const link = await this.repositories.linkForRepository(ws.id, id);
    const policy = await this.prisma.repositorySecurityPolicy.findFirst({
      where: { workspaceId: ws.id, sourceRepositoryId: id },
    });
    const baseline = await this.gates.latestBaseline(ws.id, id);
    const scans = await this.prisma.scan.findMany({
      where: { workspaceId: ws.id }, orderBy: { createdAt: "desc" }, take: 50,
    });
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId: ws.id, repositoryId: id },
      orderBy: { createdAt: "desc" }, take: 200,
    });
    const byKind = (pred: (f: Row) => boolean) => (findings as Row[]).filter(pred).length;
    const assessments = await this.prisma.pullRequestSecurityAssessment.findMany({
      where: { workspaceId: ws.id, repositoryId: id },
      orderBy: { createdAt: "desc" }, take: 20,
    });
    return {
      repository,
      link,
      policy,
      baseline,
      findingCounts: {
        total: findings.length,
        sast: byKind((f) => ((f.ruleId as string) ?? "").length > 0 && f.sourceDomain === "CODE"),
        sca: byKind((f) => Boolean(f.componentPurl)),
        secrets: byKind((f) => ((f.vulnClass as string) ?? "").toUpperCase().includes("SECRET")),
        sbom: byKind((f) => ((f.vulnClass as string) ?? "").toUpperCase().includes("SBOM")),
        container: byKind((f) => f.sourceDomain === "CONTAINER"),
      },
      recentScans: scans.slice(0, 10),
      recentPullRequestAssessments: assessments,
    };
  }

  @Get("repositories/:id/policy")
  async getPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.repositories.getPolicy(user, ws.id, id);
  }

  @Patch("repositories/:id/policy")
  async updatePolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.repositories.updatePolicy(user, ws.id, id, parseOrThrow(updateRepositoryPolicySchema, body ?? {}));
  }

  @Post("repositories/:id/baseline")
  async createBaseline(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.gates.createBaseline(user, ws.id, id, parseOrThrow(createBaselineSchema, body ?? {}));
  }

  @Get("gate-policies")
  async listGatePolicies(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.gates.listPolicies(user, ws.id);
  }

  @Post("gate-policies")
  async createGatePolicy(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.gates.createPolicy(user, ws.id, parseOrThrow(createGatePolicySchema, body ?? {}));
  }

  @Get("pipelines/:id")
  async pipeline(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.cicd.getPipelineRun(user, ws.id, id);
  }

  @Post("pipelines/:id/refresh")
  async refreshPipeline(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.cicd.refreshPipelineRun(user, ws.id, id);
  }

  @Get("pull-requests")
  async pullRequests(@CurrentUser() user: RequestUser, @Query("repositoryId") repositoryId?: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.cicd.listPullRequestAssessments(user, ws.id, repositoryId);
  }

  @Get("pull-requests/:id")
  async pullRequest(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.cicd.getPullRequestAssessment(user, ws.id, id);
  }

  @Post("pull-requests/:id/refresh")
  async refreshPullRequest(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const updated = await this.webhooks.completePullRequestAssessment(ws.id, id, user.id);
    if (!updated) throw new NotFoundException("Pull request assessment not found");
    return updated;
  }

  @Get("pull-requests/:id/sarif")
  async sarif(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.cicd.sarifForAssessment(user, ws.id, id);
  }
}
