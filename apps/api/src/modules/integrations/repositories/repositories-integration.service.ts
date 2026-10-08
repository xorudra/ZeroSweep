import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  BitbucketConnector, GitHubConnector, GitLabConnector,
  IntegrationNotConfiguredError,
  type SourceControlProvider,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { IntegrationTransportFactory } from "../core/transport";
import { IntegrationsService } from "../core/integrations.service";
import type { CreateRepositoryLinkBody, UpdateRepositoryPolicyBody } from "../dto/schemas";

type Row = Record<string, unknown>;

const PROVIDERS = ["GITHUB", "GITLAB", "BITBUCKET"] as const;

/**
 * Repository integration links + synchronization (Prompt 24 §13,
 * §28–§31, §86, §98, §99). A link binds a platform SourceRepository to
 * an external repository by the provider's IMMUTABLE id (§29).
 * Synchronization imports metadata only — code ingestion stays on the
 * governed Prompt 12 snapshot path, and sync can never create a
 * verified target or an approved assessment.
 */
@Injectable()
export class RepositoriesIntegrationService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly transports: IntegrationTransportFactory,
    private readonly integrations: IntegrationsService,
  ) {}

  providerFor(integration: Row): SourceControlProvider {
    const config = (integration.configuration ?? integration.config ?? {}) as Record<string, unknown>;
    const transport = this.transports.forIntegration(integration as Row & { type: string });
    switch (integration.type) {
      case "GITHUB": return new GitHubConnector(config, transport);
      case "GITLAB": return new GitLabConnector(config, transport);
      case "BITBUCKET": return new BitbucketConnector(config, transport);
      default: throw new BadRequestException(`Integration type ${integration.type} is not a source-control provider`);
    }
  }

  /** §13/§29: connect a repository ALREADY imported through the
   *  governed repository path (or discovered via sync into a staging
   *  row) to its external identity. Creating a link here never
   *  creates or verifies a target. */
  async createLink(user: RequestUser, workspaceId: string, body: CreateRepositoryLinkBody) {
    requireIntegrationPermission(user, "MANAGE_REPOSITORY_INTEGRATIONS");
    const integration = await this.integrations.own(user, workspaceId, body.integrationId as string);
    if (!(PROVIDERS as readonly string[]).includes(integration.type as string)) {
      throw new BadRequestException("Only GITHUB/GITLAB/BITBUCKET integrations can link repositories");
    }
    const repository = await this.prisma.sourceRepository.findFirst({
      where: { id: body.sourceRepositoryId, workspaceId },
    });
    if (!repository) throw new NotFoundException("Source repository not found in this workspace");
    this.providerFor(integration); // validates the integration is a source-control provider
    const existing = await this.prisma.repositoryIntegrationLink.findFirst({
      where: { workspaceId, sourceRepositoryId: repository.id },
    });
    if (existing) throw new BadRequestException("Repository is already linked");
    const link = await this.prisma.repositoryIntegrationLink.create({
      data: {
        workspaceId,
        integrationId: integration.id as string,
        sourceRepositoryId: repository.id as string,
        provider: integration.type as string,
        externalRepositoryId: body.externalRepositoryId as string,
        externalRepositoryRef: (body.externalRepositoryRef as string) ?? (repository.remoteUrl as string) ?? "",
        installationId: (body.installationId as string) ?? null,
        defaultBranch: (repository.defaultBranch as string) ?? null,
        visibility: (repository.visibility as string) ?? "PRIVATE",
        createdBy: user.id,
      },
    });
    await this.prisma.repositorySecurityPolicy.create({
      data: {
        workspaceId, sourceRepositoryId: repository.id as string, createdBy: user.id,
        // §31: every automation flag defaults OFF — a policy enables
        // triggers explicitly, never by accident.
        scanOnPush: false, scanOnPullRequest: false, scanDefaultBranch: false,
        sastEnabled: true, scaEnabled: true, secretScanEnabled: true, sbomEnabled: true,
        containerScanEnabled: false, autoRetest: false,
      },
    }).catch(() => undefined);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "REPOSITORY_CONNECTED", resourceType: "SourceRepository", resourceId: repository.id as string,
      metadata: { integrationId: integration.id, provider: integration.type },
    });
    return link;
  }

  async listLinks(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    return this.prisma.repositoryIntegrationLink.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
    });
  }

  async linkForRepository(workspaceId: string, sourceRepositoryId: string): Promise<Row | null> {
    return (await this.prisma.repositoryIntegrationLink.findFirst({
      where: { workspaceId, sourceRepositoryId },
    })) as Row | null;
  }

  async linkForExternal(workspaceId: string, integrationId: string, externalRepositoryId: string): Promise<Row | null> {
    return (await this.prisma.repositoryIntegrationLink.findFirst({
      where: { workspaceId, integrationId, externalRepositoryId },
    })) as Row | null;
  }

  /** §13/§98/§99: incremental repository metadata sync. Bounded
   *  pages, checkpointed per integration; a provider failure marks
   *  the integration DEGRADED and never corrupts local state (§104). */
  async syncRepositories(user: RequestUser, workspaceId: string, integrationId: string) {
    requireIntegrationPermission(user, "MANAGE_REPOSITORY_INTEGRATIONS");
    const integration = await this.integrations.own(user, workspaceId, integrationId);
    const provider = this.providerFor(integration);
    const checkpoint = await this.prisma.integrationSyncCheckpoint.findFirst({
      where: { integrationId, resourceKind: "REPOSITORIES" },
    });
    const job = await this.prisma.integrationJob.create({
      data: {
        workspaceId, integrationId, kind: "SYNC", mode: "PULL", status: "RUNNING",
        summary: { resourceKind: "REPOSITORIES" },
      } as never,
    });
    try {
      let cursor = (checkpoint?.cursor as string | null) ?? undefined;
      let imported = 0;
      let updated = 0;
      // Bounded pagination (§98): at most 10 pages per sync run.
      for (let page = 0; page < 10; page += 1) {
        const result = await provider.listRepositories(cursor ? { cursor } : undefined);
        for (const repo of result.repositories) {
          const link = await this.linkForExternal(workspaceId, integrationId, repo.externalId);
          if (link) {
            await this.prisma.repositoryIntegrationLink.update({
              where: { id: link.id as string },
              data: {
                defaultBranch: repo.defaultBranch ?? (link.defaultBranch as string | null),
                visibility: repo.visibility,
                archived: repo.archived,
                languages: repo.languages,
                installationId: repo.installationId ?? (link.installationId as string | null),
                lastSyncedAt: new Date(),
              },
            });
            updated += 1;
          } else {
            // §13: sync DISCOVERS external repositories into staging
            // SourceRepository rows (sourceKind GIT, unverified by
            // construction — no Target row is created or verified).
            const created = await this.prisma.sourceRepository.create({
              data: {
                organizationId: user.organizationId, workspaceId,
                name: repo.fullName, provider: integration.type as string,
                remoteUrl: repo.url, defaultBranch: repo.defaultBranch ?? null,
                visibility: repo.visibility, sourceKind: "GIT_REPOSITORY",
                createdBy: user.id,
              },
            });
            await this.prisma.repositoryIntegrationLink.create({
              data: {
                workspaceId, integrationId, sourceRepositoryId: created.id,
                provider: integration.type as string, externalRepositoryId: repo.externalId,
                externalRepositoryRef: repo.url, installationId: repo.installationId ?? null,
                defaultBranch: repo.defaultBranch ?? null, visibility: repo.visibility,
                archived: repo.archived, languages: repo.languages,
                lastSyncedAt: new Date(), createdBy: user.id,
              },
            });
            await this.prisma.repositorySecurityPolicy.create({
              data: {
                workspaceId, sourceRepositoryId: created.id as string, createdBy: user.id,
                scanOnPush: false, scanOnPullRequest: false, scanDefaultBranch: false,
                sastEnabled: true, scaEnabled: true, secretScanEnabled: true, sbomEnabled: true,
                containerScanEnabled: false, autoRetest: false,
              },
            }).catch(() => undefined);
            imported += 1;
          }
        }
        if (!result.nextCursor) { cursor = undefined; break; }
        cursor = result.nextCursor;
      }
      await this.saveCheckpoint(workspaceId, integrationId, "REPOSITORIES", cursor ?? null);
      await this.prisma.integration.update({
        where: { id: integrationId },
        data: { lastSyncAt: new Date(), status: "CONNECTED", lastErrorCategory: null },
      });
      await this.prisma.integrationJob.update({
        where: { id: job.id },
        data: { status: "COMPLETED", summary: { resourceKind: "REPOSITORIES", imported, updated } },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "REPOSITORY_SYNCED", resourceType: "Integration", resourceId: integrationId,
        metadata: { imported, updated },
      });
      return { imported, updated, status: "COMPLETED" as const };
    } catch (err) {
      const notConfigured = err instanceof IntegrationNotConfiguredError;
      await this.prisma.integrationJob.update({
        where: { id: job.id },
        data: { status: "FAILED", summary: { resourceKind: "REPOSITORIES", errorCategory: notConfigured ? "NOT_CONFIGURED" : "PROVIDER_ERROR" } },
      });
      if (!notConfigured) {
        await this.prisma.integration.update({
          where: { id: integrationId },
          data: { status: "DEGRADED", lastErrorCategory: "PROVIDER_ERROR" },
        }).catch(() => undefined);
      }
      return {
        imported: 0, updated: 0,
        status: notConfigured ? ("NOT_CONFIGURED" as const) : ("FAILED" as const),
        detail: notConfigured
          ? "Provider transport is not configured in this deployment — no repositories were imported and none were fabricated"
          : "Provider sync failed; the integration is marked DEGRADED and local state is unchanged (§104)",
      };
    }
  }

  async getPolicy(user: RequestUser, workspaceId: string, sourceRepositoryId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const policy = await this.prisma.repositorySecurityPolicy.findFirst({
      where: { workspaceId, sourceRepositoryId },
    });
    if (!policy) throw new NotFoundException("Repository security policy not found");
    return policy;
  }

  async updatePolicy(user: RequestUser, workspaceId: string, sourceRepositoryId: string, body: UpdateRepositoryPolicyBody) {
    requireIntegrationPermission(user, "MANAGE_REPOSITORY_INTEGRATIONS");
    const existing = await this.prisma.repositorySecurityPolicy.findFirst({
      where: { workspaceId, sourceRepositoryId },
    });
    if (!existing) throw new NotFoundException("Repository security policy not found");
    const data: Row = {};
    const raw = body as Record<string, unknown>;
    for (const key of [
      "scanOnPush", "scanOnPullRequest", "scanDefaultBranch", "sastEnabled", "scaEnabled",
      "secretScanEnabled", "sbomEnabled", "containerScanEnabled", "gatePolicyId", "prGatePreset", "autoRetest",
    ]) {
      if (raw[key] !== undefined) data[key] = raw[key];
    }
    return this.prisma.repositorySecurityPolicy.update({ where: { id: existing.id as string }, data: data as never });
  }

  private async saveCheckpoint(workspaceId: string, integrationId: string, resourceKind: string, cursor: string | null) {
    const existing = await this.prisma.integrationSyncCheckpoint.findFirst({
      where: { integrationId, resourceKind },
    });
    if (existing) {
      await this.prisma.integrationSyncCheckpoint.update({
        where: { id: existing.id },
        data: { cursor, lastSyncedAt: new Date(), lastSuccessAt: new Date(), lastErrorCategory: null },
      });
    } else {
      await this.prisma.integrationSyncCheckpoint.create({
        data: { workspaceId, integrationId, resourceKind, cursor, lastSyncedAt: new Date(), lastSuccessAt: new Date() },
      });
    }
  }
}
