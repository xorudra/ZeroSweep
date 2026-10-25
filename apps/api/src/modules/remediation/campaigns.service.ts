import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { computeCampaignProgress, findingMatchesCampaignScope } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService, type CaseRow } from "./case-state.service";
import { RemediationCasesService } from "./cases.service";
import { requireRemediationPermission } from "./permissions";

type CampaignRow = Awaited<ReturnType<PrismaClientLike["remediationCampaign"]["findFirstOrThrow"]>>;

/**
 * Remediation campaigns (Prompt 31 §87–§92). A campaign groups the
 * cases for one CVE / one vulnerable dependency / one technology / one
 * KEV push. Membership is derived from the scope against REAL findings
 * (cases are ensured for matching canonical findings), and progress is
 * computed from live case states — never stored counters (§90).
 * Patch campaigns (§91) group by product + affected/fixed versions via
 * the finding's own component data.
 */
@Injectable()
export class RemediationCampaignsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly cases: RemediationCasesService,
  ) {}

  async createCampaign(user: RequestUser, workspaceId: string, input: {
    name: string; scope: { cve?: string; componentPurl?: string; product?: string; technology?: string; kevOnly?: boolean };
    ownerId?: string; targetDate?: Date; idempotencyKey?: string; autoCollect?: boolean;
  }) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_CAMPAIGN");
    if (!input.name?.trim()) throw new BadRequestException("campaign name is required");
    if (input.idempotencyKey) {
      const existing = await this.prisma.remediationCampaign.findFirst({ where: { idempotencyKey: input.idempotencyKey } });
      if (existing) {
        if (existing.workspaceId !== workspaceId) throw new BadRequestException("campaign idempotency key collision across workspaces");
        return { campaign: existing as CampaignRow, created: false, collected: 0 };
      }
    }
    const campaign = await this.prisma.remediationCampaign.create({
      data: {
        workspaceId, name: input.name, scope: input.scope as never,
        ownerId: input.ownerId ?? null, targetDate: input.targetDate ?? null,
        idempotencyKey: input.idempotencyKey ?? null, createdBy: user.id,
      },
    }) as CampaignRow;
    await this.state.publishEvent(workspaceId, "REMEDIATION_CAMPAIGN_CREATED", "REMEDIATION_CAMPAIGN", campaign.id, { name: input.name, createdBy: user.id });
    let collected = 0;
    if (input.autoCollect !== false) {
      collected = await this.collect(user, workspaceId, campaign);
    }
    return { campaign, created: true, collected };
  }

  /** Collect matching findings into the campaign, ensuring cases (§87). */
  async collect(user: RequestUser, workspaceId: string, campaign: CampaignRow): Promise<number> {
    const scope = campaign.scope as { cve?: string; componentPurl?: string; product?: string; technology?: string; kevOnly?: boolean };
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId, duplicateOfId: null }, take: 5000,
    });
    let added = 0;
    for (const finding of findings) {
      if (!findingMatchesCampaignScope(scope, finding)) continue;
      const { case: kase } = await this.cases.ensureCase(user, workspaceId, finding.id);
      const existing = await this.prisma.remediationCampaignCase.findFirst({
        where: { campaignId: campaign.id, caseId: kase.id },
      });
      if (!existing) {
        await this.prisma.remediationCampaignCase.create({
          data: { campaignId: campaign.id, caseId: kase.id, workspaceId },
        });
        added += 1;
      }
    }
    return added;
  }

  async addCase(user: RequestUser, workspaceId: string, campaignId: string, caseId: string) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_CAMPAIGN");
    const campaign = await this.getCampaign(workspaceId, campaignId);
    const kase = await this.state.getCase(workspaceId, caseId);
    const existing = await this.prisma.remediationCampaignCase.findFirst({ where: { campaignId, caseId } });
    if (existing) return { campaign, case: kase, added: false };
    await this.prisma.remediationCampaignCase.create({ data: { campaignId, caseId, workspaceId } });
    return { campaign, case: kase, added: true };
  }

  async getCampaign(workspaceId: string, campaignId: string): Promise<CampaignRow> {
    const campaign = await this.prisma.remediationCampaign.findFirst({ where: { id: campaignId, workspaceId } });
    if (!campaign) throw new BadRequestException("campaign not found in this workspace");
    return campaign as CampaignRow;
  }

  async listCampaigns(workspaceId: string, now = new Date()) {
    const campaigns = await this.prisma.remediationCampaign.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const out = [];
    for (const campaign of campaigns as CampaignRow[]) {
      out.push({ campaign, progress: await this.progress(workspaceId, campaign.id, now) });
    }
    return out;
  }

  async progress(workspaceId: string, campaignId: string, now = new Date()) {
    const links = await this.prisma.remediationCampaignCase.findMany({ where: { campaignId, workspaceId } });
    const cases: Array<{ status: string; dueAt: Date | null }> = [];
    for (const link of links) {
      const kase = await this.prisma.remediationCase.findFirst({ where: { id: link.caseId, workspaceId } });
      if (kase) cases.push({ status: kase.status, dueAt: kase.dueAt });
    }
    return computeCampaignProgress(cases as never, now);
  }

  /** §92: SBOM remediation view — where a vulnerable component lives:
   *  repositories, direct/transitive scope, images and assets, taken
   *  from the findings/components the platform already recorded. */
  async sbomExposure(workspaceId: string, componentPurl: string) {
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId, componentPurl, duplicateOfId: null }, take: 1000,
    });
    const repositories = new Set<string>();
    const assets = new Set<string>();
    const images = new Set<string>();
    let direct = 0;
    let transitive = 0;
    for (const f of findings) {
      if (f.repositoryId) repositories.add(f.repositoryId);
      if (f.assetId) assets.add(f.assetId);
      if (f.imageRef) images.add(f.imageRef);
      if (f.dependencyScope === "DIRECT") direct += 1;
      if (f.dependencyScope === "TRANSITIVE") transitive += 1;
    }
    return {
      componentPurl,
      findings: findings.length,
      repositories: [...repositories], assets: [...assets], images: [...images],
      direct, transitive,
    };
  }
}
