import { createHash } from "node:crypto";
import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";
import { EasmDiscoveryService } from "../discovery/discovery.service";

type Row = Record<string, unknown>;

/**
 * Drift queue + baselines (Prompt 29 §80–§85, §102). Baselines are
 * immutable and versioned: creating one snapshots the CURRENT trusted
 * state as a new version row; old versions are never edited.
 */
@Injectable()
export class EasmDriftService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly discovery: EasmDiscoveryService,
  ) {}

  async listDrift(user: RequestUser, workspaceId: string, filters: { programId?: string; type?: string; severity?: string; status?: string; candidateId?: string }) {
    requireEasmPermission(user, "VIEW_EASM");
    const where: Row = { workspaceId };
    if (filters.programId) where.programId = filters.programId;
    if (filters.type) where.type = filters.type;
    if (filters.severity) where.severity = filters.severity;
    if (filters.status) where.status = filters.status;
    if (filters.candidateId) where.candidateId = filters.candidateId;
    const items = await this.prisma.easmDriftEvent.findMany({ where: where as never, orderBy: { detectedAt: "desc" }, take: 300 });
    return { items, total: items.length };
  }

  async acknowledgeDrift(user: RequestUser, workspaceId: string, driftId: string) {
    requireEasmPermission(user, "ACKNOWLEDGE_EASM_DRIFT");
    const drift = await this.prisma.easmDriftEvent.findFirst({ where: { id: driftId, workspaceId } });
    if (!drift) throw new NotFoundException("Drift event not found");
    return this.prisma.easmDriftEvent.update({ where: { id: driftId }, data: { status: "ACKNOWLEDGED" } });
  }

  async listBaselines(user: RequestUser, workspaceId: string, programId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const items = await this.prisma.easmBaseline.findMany({ where: { workspaceId, programId }, orderBy: { version: "desc" } });
    return { items, total: items.length };
  }

  async createBaseline(user: RequestUser, workspaceId: string, programId: string) {
    requireEasmPermission(user, "MANAGE_EASM");
    const program = await this.prisma.easmProgram.findFirst({ where: { id: programId, workspaceId } });
    if (!program) throw new NotFoundException("EASM program not found");
    const snapshot = await this.discovery.buildSnapshot(workspaceId, programId);
    const latest = await this.prisma.easmBaseline.findFirst({ where: { workspaceId, programId }, orderBy: { version: "desc" } });
    const version = ((latest?.version as number | undefined) ?? 0) + 1;
    const contentHash = createHash("sha256").update(JSON.stringify(snapshot)).digest("hex");
    const baseline = await this.prisma.easmBaseline.create({
      data: { workspaceId, programId, version, snapshot: snapshot as never, contentHash, createdBy: user.id },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_BASELINE_CREATED", resourceType: "EasmBaseline", resourceId: baseline.id,
      metadata: { programId, version, contentHash },
    }).catch(() => undefined);
    return baseline;
  }
}
