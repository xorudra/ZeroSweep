import { createHash } from "node:crypto";
import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";
import { EasmAnalyticsService } from "../analytics/analytics.service";

type Row = Record<string, unknown>;

/**
 * EASM reporting (Prompt 29 §120/§121). Reports are immutable,
 * hash-anchored snapshots rendered from REAL EASM rows at generation
 * time, in the P20 snapshot discipline — a report is a record of
 * what the platform knew, never a live view and never embellished.
 */
@Injectable()
export class EasmReportsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly analytics: EasmAnalyticsService,
  ) {}

  async generate(user: RequestUser, workspaceId: string, input: { type: string; programId?: string }) {
    requireEasmPermission(user, "EXPORT_EASM");
    const programId = input.programId;
    const where: Row = { workspaceId };
    if (programId) where.programId = programId;
    const candidates = (await this.prisma.easmAssetCandidate.findMany({ where: where as never, take: 5000 })) as Row[];
    const dashboard = await this.analytics.dashboard(user, workspaceId, programId);
    let content: Row;
    switch (input.type) {
      case "NEW_ASSET": {
        const weekAgo = Date.now() - 7 * 86_400_000;
        content = { newAssets: candidates.filter((c) => new Date(c.firstSeen as string).getTime() >= weekAgo).map((c) => this.brief(c)) };
        break;
      }
      case "UNKNOWN_ASSET": {
        content = { unknownAssets: candidates.filter((c) => c.ownershipStatus === "UNKNOWN").map((c) => this.brief(c)) };
        break;
      }
      case "EXPOSURE_DRIFT": {
        const drift = await this.prisma.easmDriftEvent.findMany({ where: where as never, orderBy: { detectedAt: "desc" }, take: 500 });
        content = { drift };
        break;
      }
      case "CERTIFICATE_HEALTH": {
        const certs = await this.prisma.easmCertificate.findMany({ where: { workspaceId }, orderBy: { notAfter: "asc" }, take: 1000 });
        content = { certificateHealth: dashboard.certificateHealth, certificates: certs };
        break;
      }
      case "TECHNOLOGY_EXPOSURE": {
        content = { technologies: (await this.analytics.technologies(user, workspaceId, programId)).items };
        break;
      }
      case "EXECUTIVE_EASM": {
        content = {
          attackSurfaceSize: dashboard.totalExternalAssets,
          growthNewThisWeek: dashboard.newAssetsThisWeek,
          unknownAssets: dashboard.unknownAssets,
          criticalExposure: dashboard.criticalExposures,
          kevExposure: dashboard.kevExposure,
          sensitiveServices: dashboard.sensitiveServices,
          certificateHealth: dashboard.certificateHealth,
          topTechnologies: (await this.analytics.technologies(user, workspaceId, programId)).items.slice(0, 10),
          importantDrift: dashboard.recentDrift,
          ownershipCoverage: dashboard.ownershipCoverage,
        };
        break;
      }
      default: { // EXTERNAL_ATTACK_SURFACE
        content = { dashboard, assets: candidates.map((c) => this.brief(c)) };
      }
    }
    const contentHash = createHash("sha256").update(JSON.stringify(content)).digest("hex");
    const snapshot = await this.prisma.easmReportSnapshot.create({
      data: { workspaceId, programId: programId ?? null, type: input.type, content: content as never, contentHash, generatedBy: user.id },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "REPORT_GENERATED", resourceType: "EasmReportSnapshot", resourceId: snapshot.id,
      metadata: { type: input.type, contentHash },
    }).catch(() => undefined);
    return snapshot;
  }

  private brief(c: Row): Row {
    return {
      id: c.id, value: c.normalizedValue, type: c.type, ownershipStatus: c.ownershipStatus,
      exposureState: c.exposureState, activeTestingStatus: c.activeTestingStatus,
      lifecycle: c.lifecycle, firstSeen: c.firstSeen, lastSeen: c.lastSeen,
    };
  }

  async list(user: RequestUser, workspaceId: string, type?: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const where: Row = { workspaceId };
    if (type) where.type = type;
    const items = await this.prisma.easmReportSnapshot.findMany({ where: where as never, orderBy: { createdAt: "desc" }, take: 100 });
    return { items, total: items.length };
  }
}
