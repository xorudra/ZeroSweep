import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { canPromoteCandidate } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";

type Row = Record<string, unknown>;

/**
 * Candidate inventory, review workflow, ownership rules and asset
 * promotion (Prompt 29 §70–§71, §94–§97). Promotion creates the
 * canonical Target + Asset — the Target is created UNVERIFIED and
 * the Asset PENDING_REVIEW, so the promoted asset still cannot be
 * scanned until it passes the platform's standard target
 * verification + assessment approval gates. Promotion NEVER touches
 * activeTestingStatus (§71/§135).
 */
@Injectable()
export class EasmAssetsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private async auditSafe(entry: Parameters<AuditService["record"]>[0]) {
    await this.audit.record(entry).catch(() => undefined);
  }

  async getCandidate(workspaceId: string, candidateId: string): Promise<Row> {
    const candidate = await this.prisma.easmAssetCandidate.findFirst({ where: { id: candidateId, workspaceId } });
    if (!candidate) throw new NotFoundException("EASM candidate not found");
    return candidate as Row;
  }

  async listCandidates(user: RequestUser, workspaceId: string, filters: {
    programId?: string; status?: string; ownershipStatus?: string; exposureState?: string;
    lifecycle?: string; type?: string; unknownOnly?: boolean; limit?: number;
  }) {
    requireEasmPermission(user, "VIEW_EASM");
    const where: Row = { workspaceId };
    if (filters.programId) where.programId = filters.programId;
    if (filters.status) where.status = filters.status;
    if (filters.ownershipStatus) where.ownershipStatus = filters.ownershipStatus;
    if (filters.exposureState) where.exposureState = filters.exposureState;
    if (filters.lifecycle) where.lifecycle = filters.lifecycle;
    if (filters.type) where.type = filters.type;
    if (filters.unknownOnly) where.ownershipStatus = "UNKNOWN";
    const items = await this.prisma.easmAssetCandidate.findMany({
      where: where as never, orderBy: { lastSeen: "desc" }, take: Math.min(filters.limit ?? 200, 500),
    });
    return { items, total: items.length };
  }

  /** §97 unknown-asset queue with evidence + recommended review. */
  async unknownQueue(user: RequestUser, workspaceId: string, programId?: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const where: Row = { workspaceId, ownershipStatus: "UNKNOWN" };
    if (programId) where.programId = programId;
    const items = (await this.prisma.easmAssetCandidate.findMany({ where: where as never, orderBy: { firstSeen: "asc" }, take: 200 })) as Row[];
    const enriched = [];
    for (const c of items) {
      const observations = await this.prisma.assetDiscoveryObservation.findMany({
        where: { workspaceId, candidateId: c.id as string }, orderBy: { observedAt: "desc" }, take: 5,
      });
      enriched.push({
        ...c,
        discoverySources: [...new Set(observations.map((o) => (o as Row).source as string))],
        evidence: observations,
        recommendedReview: c.exposureState === "INTERNET_EXPOSED"
          ? "Internet-exposed with unknown ownership — confirm ownership or declare third-party/shared promptly"
          : "Review discovery evidence; verify ownership or reject the candidate",
      });
    }
    return { items: enriched, total: enriched.length };
  }

  async candidateDetail(user: RequestUser, workspaceId: string, candidateId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const candidate = await this.getCandidate(workspaceId, candidateId);
    const [observations, dnsSnapshots, services, httpSnapshots, technologies, relationships, drift, evidence, screenshots] = await Promise.all([
      this.prisma.assetDiscoveryObservation.findMany({ where: { workspaceId, candidateId }, orderBy: { observedAt: "desc" }, take: 100 }),
      this.prisma.dnsSnapshot.findMany({ where: { workspaceId, candidateId }, orderBy: { observedAt: "desc" }, take: 20 }),
      this.prisma.serviceObservation.findMany({ where: { workspaceId, candidateId } }),
      this.prisma.httpExposureSnapshot.findMany({ where: { workspaceId, candidateId }, orderBy: { capturedAt: "desc" }, take: 20 }),
      this.prisma.technologyObservation.findMany({ where: { workspaceId, candidateId } }),
      this.prisma.easmAssetRelationship.findMany({ where: { workspaceId, fromId: candidateId } }),
      this.prisma.easmDriftEvent.findMany({ where: { workspaceId, candidateId }, orderBy: { detectedAt: "desc" }, take: 50 }),
      this.prisma.easmOwnershipEvidence.findMany({ where: { workspaceId, candidateId }, orderBy: { createdAt: "desc" } }),
      this.prisma.easmScreenshot.findMany({ where: { workspaceId, candidateId } }),
    ]);
    const findings = candidate.promotedAssetId
      ? await this.prisma.finding.findMany({ where: { assetId: candidate.promotedAssetId as string }, take: 50 }).catch(() => [])
      : [];
    return {
      candidate, observations, dnsSnapshots, services, httpSnapshots, technologies,
      relationships, drift, ownershipEvidence: evidence,
      // §52/§147: screenshot METADATA is listed for everyone with
      // VIEW_EASM; the storage key (needed to fetch bytes) is only
      // exposed to VIEW_EASM_EVIDENCE holders.
      screenshots: screenshots.map((s) => {
        const row = s as Row;
        const canSee = user.role === "OWNER" || user.role === "ADMIN" || user.role === "SECURITY_ENGINEER";
        return canSee ? row : { ...row, storageKey: null };
      }),
      findings,
    };
  }

  /** §51/§52/§147: screenshot byte access gate — DENIED without
   *  VIEW_EASM_EVIDENCE, and every attempt is audited. */
  async getScreenshot(user: RequestUser, workspaceId: string, screenshotId: string) {
    const shot = await this.prisma.easmScreenshot.findFirst({ where: { id: screenshotId, workspaceId } });
    if (!shot) throw new NotFoundException("Screenshot not found");
    const allowed = user.role === "OWNER" || user.role === "ADMIN" || user.role === "SECURITY_ENGINEER";
    await this.auditSafe({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RAW_EVIDENCE_ACCESSED", resourceType: "EasmScreenshot", resourceId: screenshotId,
      metadata: { outcome: allowed ? "ALLOWED" : "DENIED", via: "VIEW_EASM_EVIDENCE" },
    });
    if (!allowed) {
      throw new ForbiddenException("Missing EASM permission: VIEW_EASM_EVIDENCE");
    }
    return shot;
  }

  async patchCandidate(user: RequestUser, workspaceId: string, candidateId: string, input: {
    action: string; mergedIntoId?: string; criticality?: string;
    technicalOwner?: string; businessOwner?: string; team?: string; application?: string; businessUnit?: string;
  }) {
    const candidate = await this.getCandidate(workspaceId, candidateId);
    switch (input.action) {
      case "REVIEW": {
        requireEasmPermission(user, "MANAGE_EASM");
        return this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: { status: "REVIEWING" } });
      }
      case "CONFIRM": {
        requireEasmPermission(user, "MANAGE_EASM");
        return this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: { status: "CONFIRMED" } });
      }
      case "REJECT": {
        requireEasmPermission(user, "MANAGE_EASM");
        const updated = await this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: { status: "REJECTED", lifecycle: "ARCHIVED" } });
        await this.auditSafe({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "EASM_ASSET_REJECTED", resourceType: "EasmAssetCandidate", resourceId: candidateId, metadata: {},
        });
        return updated;
      }
      case "MERGE": {
        requireEasmPermission(user, "MANAGE_EASM");
        if (!input.mergedIntoId) throw new BadRequestException("mergedIntoId is required for MERGE");
        await this.getCandidate(workspaceId, input.mergedIntoId);
        return this.prisma.easmAssetCandidate.update({
          where: { id: candidateId }, data: { status: "MERGED", mergedIntoId: input.mergedIntoId, lifecycle: "ARCHIVED" },
        });
      }
      case "DECLARE_THIRD_PARTY": {
        requireEasmPermission(user, "MANAGE_EASM");
        await this.prisma.easmOwnershipEvidence.create({
          data: { workspaceId, candidateId, kind: "THIRD_PARTY_DECLARATION", reference: `manual:${user.id}`, createdBy: user.id, detail: "declared third-party by reviewer" },
        });
        const updated = await this.prisma.easmAssetCandidate.update({
          where: { id: candidateId }, data: { ownershipStatus: "THIRD_PARTY", ownershipConfidence: "HIGH" },
        });
        await this.auditSafe({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "EASM_OWNERSHIP_CHANGED", resourceType: "EasmAssetCandidate", resourceId: candidateId,
          metadata: { from: candidate.ownershipStatus, to: "THIRD_PARTY" },
        });
        return updated;
      }
      case "DECLARE_SHARED": {
        requireEasmPermission(user, "MANAGE_EASM");
        await this.prisma.easmOwnershipEvidence.create({
          data: { workspaceId, candidateId, kind: "SHARED_INFRASTRUCTURE", reference: `manual:${user.id}`, createdBy: user.id, detail: "declared shared infrastructure by reviewer" },
        });
        return this.prisma.easmAssetCandidate.update({
          where: { id: candidateId }, data: { ownershipStatus: "SHARED", ownershipConfidence: "MEDIUM" },
        });
      }
      case "SET_CRITICALITY": {
        requireEasmPermission(user, "MANAGE_EASM");
        if (!input.criticality) throw new BadRequestException("criticality is required");
        return this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: { criticality: input.criticality } });
      }
      case "ASSIGN_OWNER": {
        requireEasmPermission(user, "MANAGE_ASSET_OWNERS");
        const data: Row = {};
        for (const key of ["technicalOwner", "businessOwner", "team", "application", "businessUnit"]) {
          if (input[key as keyof typeof input] !== undefined) data[key] = input[key as keyof typeof input];
        }
        return this.prisma.easmAssetCandidate.update({ where: { id: candidateId }, data: data as never });
      }
      default:
        throw new BadRequestException(`Unknown candidate action: ${input.action}`);
    }
  }

  /**
   * §70/§71: promote a candidate into the canonical inventory.
   * Creates an UNVERIFIED Target + PENDING_REVIEW Asset. The
   * platform's scan gates (target VERIFIED + assessment APPROVED)
   * still stand between this asset and any active testing.
   */
  async promoteCandidate(user: RequestUser, workspaceId: string, candidateId: string) {
    requireEasmPermission(user, "MANAGE_EASM");
    const candidate = await this.getCandidate(workspaceId, candidateId);
    if (candidate.status === "MERGED" || candidate.status === "REJECTED") {
      throw new BadRequestException(`Candidate is ${candidate.status} and cannot be promoted`);
    }
    if (candidate.promotedAssetId) return candidate; // idempotent
    const policy = await this.prisma.easmDiscoveryPolicy.findFirst({ where: { workspaceId, programId: candidate.programId as string } });
    const gate = canPromoteCandidate({
      ownershipStatus: candidate.ownershipStatus as never,
      ownershipConfidence: candidate.ownershipConfidence as never,
      policyAllowsPromotion: policy?.allowPromotion !== false,
    });
    if (!gate.allowed) throw new BadRequestException(`Promotion refused: ${gate.reason}`);
    const targetType = candidate.type === "IP" ? "IP_ADDRESS" : candidate.type === "URL" ? "WEB_APPLICATION" : "DOMAIN";
    const target = await this.prisma.target.create({
      data: {
        workspaceId, name: `EASM: ${candidate.normalizedValue as string}`, type: targetType as never,
        value: candidate.normalizedValue as string,
        description: "Promoted from EASM candidate. NOT verified — standard target verification is still required before any assessment.",
        status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const asset = await this.prisma.asset.create({
      data: {
        workspaceId, targetId: target.id, host: candidate.normalizedValue as string,
        type: candidate.type === "IP" ? "IP" : "HOST",
        scopeStatus: "PENDING_REVIEW", sources: ["easm"],
        criticality: candidate.criticality as string,
      },
    });
    const updated = await this.prisma.easmAssetCandidate.update({
      where: { id: candidateId },
      data: { status: "CONFIRMED", promotedAssetId: asset.id, promotedTargetId: target.id },
    });
    await this.auditSafe({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_ASSET_PROMOTED", resourceType: "EasmAssetCandidate", resourceId: candidateId,
      metadata: { targetId: target.id, assetId: asset.id, targetVerified: false, activeTestingStatus: candidate.activeTestingStatus },
    });
    return updated;
  }

  /* ---------------------------- ownership rules ---------------------------- */

  async listOwnershipRules(user: RequestUser, workspaceId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const items = await this.prisma.assetOwnershipRule.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    return { items, total: items.length };
  }

  async createOwnershipRule(user: RequestUser, workspaceId: string, input: Row) {
    requireEasmPermission(user, "MANAGE_ASSET_OWNERS");
    return this.prisma.assetOwnershipRule.create({
      data: {
        workspaceId, programId: (input.programId as string) ?? null,
        ruleType: input.ruleType as string, pattern: input.pattern as string,
        ownershipStatus: (input.ownershipStatus as string) ?? "LIKELY",
        technicalOwner: (input.technicalOwner as string) ?? null, team: (input.team as string) ?? null,
        application: (input.application as string) ?? null, businessUnit: (input.businessUnit as string) ?? null,
        createdBy: user.id,
      },
    });
  }
}
