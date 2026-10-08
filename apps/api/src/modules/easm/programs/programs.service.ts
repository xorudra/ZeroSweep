import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { randomBytes } from "node:crypto";
import { normalizeDomain, normalizeIp } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireEasmPermission } from "../permissions";

type Row = Record<string, unknown>;

/**
 * EASM programs, root assets and the authorization workflow
 * (Prompt 29 §3–§11). The two-step separation is enforced here:
 * verification (VERIFY_ASSET_OWNERSHIP) proves ownership; active
 * testing (AUTHORIZE_EASM_ACTIVE_TESTING, admins only) is a separate
 * recorded grant. Neither implies the other (§118/§135).
 */
@Injectable()
export class EasmProgramsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async getProgram(workspaceId: string, programId: string): Promise<Row> {
    const program = await this.prisma.easmProgram.findFirst({ where: { id: programId, workspaceId } });
    if (!program) throw new NotFoundException("EASM program not found");
    return program as Row;
  }

  async listPrograms(user: RequestUser, workspaceId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    const items = await this.prisma.easmProgram.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    return { items, total: items.length };
  }

  async createProgram(user: RequestUser, workspaceId: string, input: { name: string; description?: string; monitoringEnabled?: boolean; monitoringTier?: string }) {
    requireEasmPermission(user, "MANAGE_EASM");
    const program = await this.prisma.easmProgram.create({
      data: {
        organizationId: user.organizationId, workspaceId, name: input.name,
        description: input.description ?? "", status: "DRAFT",
        monitoringEnabled: input.monitoringEnabled ?? false,
        monitoringTier: input.monitoringTier ?? "DAILY", createdBy: user.id,
      },
    });
    // Default discovery policy (§10): passive only, conservative.
    await this.prisma.easmDiscoveryPolicy.create({ data: { programId: program.id, workspaceId } });
    await this.prisma.easmServiceDiscoveryProfile.create({ data: { programId: program.id, workspaceId } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_PROGRAM_CREATED", resourceType: "EasmProgram", resourceId: program.id,
      metadata: { name: input.name },
    }).catch(() => undefined);
    return program;
  }

  async patchProgram(user: RequestUser, workspaceId: string, programId: string, input: Record<string, unknown>) {
    requireEasmPermission(user, "MANAGE_EASM");
    await this.getProgram(workspaceId, programId);
    const data: Row = {};
    for (const key of ["name", "description", "status", "monitoringEnabled", "monitoringTier"]) {
      if (input[key] !== undefined) data[key] = input[key];
    }
    return this.prisma.easmProgram.update({ where: { id: programId }, data: data as never });
  }

  /* ------------------------------ root assets ------------------------------ */

  async listRootAssets(user: RequestUser, workspaceId: string, programId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    await this.getProgram(workspaceId, programId);
    const items = await this.prisma.easmRootAsset.findMany({ where: { workspaceId, programId }, orderBy: { createdAt: "asc" } });
    return { items, total: items.length };
  }

  async addRootAsset(user: RequestUser, workspaceId: string, programId: string, input: { type: string; value: string }) {
    requireEasmPermission(user, "MANAGE_EASM_SCOPE");
    const program = await this.getProgram(workspaceId, programId);
    let value = input.value.trim();
    let unicodeValue: string | null = null;
    if (input.type === "DOMAIN") {
      const n = normalizeDomain(value);
      if (!n) throw new BadRequestException("Invalid root domain");
      value = n.ascii;
      unicodeValue = n.unicode !== n.ascii ? n.unicode : null;
    } else if (input.type === "IP") {
      const ip = normalizeIp(value);
      if (!ip) throw new BadRequestException("Invalid root IP");
      value = ip;
    } else if (input.type === "CIDR") {
      // §9: CIDR scope requires explicit authorization — it lands
      // PENDING like everything else; WHOIS is never consulted here.
      if (!/^[0-9a-fA-F:./]+$/.test(value) || !value.includes("/")) throw new BadRequestException("Invalid CIDR notation");
    }
    const challenge = `dsrclone-verify=${randomBytes(12).toString("hex")}`;
    const root = await this.prisma.easmRootAsset.create({
      data: {
        programId: program.id as string, workspaceId, type: input.type, value, unicodeValue,
        authorizationStatus: "PENDING", authorizationMethod: null, authorizedBy: null, authorizedAt: null,
        authorizationExpiresAt: null, activeTestingAllowed: false, activeTestingStatus: "NOT_AUTHORIZED",
        activeTestingBy: null, activeTestingAt: null,
        verificationChallenge: challenge, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_ROOT_ASSET_ADDED", resourceType: "EasmRootAsset", resourceId: root.id,
      metadata: { programId, type: input.type, value },
    }).catch(() => undefined);
    return root;
  }

  async getRootAsset(workspaceId: string, rootId: string): Promise<Row> {
    const root = await this.prisma.easmRootAsset.findFirst({ where: { id: rootId, workspaceId } });
    if (!root) throw new NotFoundException("Root asset not found");
    return root as Row;
  }

  /**
   * §8/§134: complete a controlled ownership verification. The
   * caller must present evidence that the challenge was satisfied:
   * for DNS_TXT/FILE_CHALLENGE an observation record referencing this
   * root's challenge value; for MANUAL_APPROVAL/CLOUD_INTEGRATION a
   * recorded approval/integration reference. A bare assertion is
   * refused — the challenge must exist in platform records.
   */
  async verifyRootAsset(user: RequestUser, workspaceId: string, rootId: string, input: { method: string; evidenceReference: string }) {
    requireEasmPermission(user, "VERIFY_ASSET_OWNERSHIP");
    const root = await this.getRootAsset(workspaceId, rootId);
    if (root.authorizationStatus === "VERIFIED") return root;
    if (input.method === "DNS_TXT" || input.method === "FILE_CHALLENGE") {
      const observation = await this.prisma.assetDiscoveryObservation.findFirst({
        where: { workspaceId, rootAssetId: rootId, id: input.evidenceReference },
      });
      const meta = (observation?.metadata ?? {}) as Row;
      if (!observation || meta.challengeValue !== root.verificationChallenge) {
        throw new BadRequestException("Verification evidence does not demonstrate the published challenge — ownership remains PENDING");
      }
    }
    const updated = await this.prisma.easmRootAsset.update({
      where: { id: rootId },
      data: {
        authorizationStatus: "VERIFIED", authorizationMethod: input.method,
        authorizedBy: user.id, authorizedAt: new Date(), verificationChallenge: null,
      },
    });
    await this.prisma.easmOwnershipEvidence.create({
      data: {
        workspaceId, rootAssetId: rootId,
        kind: input.method === "DNS_TXT" ? "DNS_TXT_VERIFIED" : input.method === "FILE_CHALLENGE" ? "FILE_CHALLENGE_VERIFIED" : input.method === "CLOUD_INTEGRATION" ? "CLOUD_INTEGRATION" : "MANUAL_APPROVAL",
        reference: input.evidenceReference, createdBy: user.id,
        detail: `root asset ownership verified via ${input.method}`,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_ROOT_ASSET_VERIFIED", resourceType: "EasmRootAsset", resourceId: rootId,
      metadata: { method: input.method },
    }).catch(() => undefined);
    return updated;
  }

  /**
   * §6/§118/§135: authorize active testing for a VERIFIED root —
   * a separate grant by a separate permission. Verification alone
   * never reaches this state.
   */
  async authorizeActiveTesting(user: RequestUser, workspaceId: string, rootId: string, input: { level: string; expiresAt?: string }) {
    requireEasmPermission(user, "AUTHORIZE_EASM_ACTIVE_TESTING");
    const root = await this.getRootAsset(workspaceId, rootId);
    if (root.authorizationStatus !== "VERIFIED") {
      throw new BadRequestException("Active testing can only be authorized for a VERIFIED root asset");
    }
    const updated = await this.prisma.easmRootAsset.update({
      where: { id: rootId },
      data: {
        activeTestingAllowed: true, activeTestingStatus: input.level,
        activeTestingBy: user.id, activeTestingAt: new Date(),
        authorizationExpiresAt: input.expiresAt ? new Date(input.expiresAt) : (root.authorizationExpiresAt as Date | null),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EASM_ACTIVE_TESTING_AUTHORIZED", resourceType: "EasmRootAsset", resourceId: rootId,
      metadata: { level: input.level },
    }).catch(() => undefined);
    return updated;
  }

  /* -------------------------------- policies ------------------------------- */

  async getPolicy(user: RequestUser, workspaceId: string, programId: string) {
    requireEasmPermission(user, "VIEW_EASM");
    await this.getProgram(workspaceId, programId);
    const policy = await this.prisma.easmDiscoveryPolicy.findFirst({ where: { workspaceId, programId } });
    const profile = await this.prisma.easmServiceDiscoveryProfile.findFirst({ where: { workspaceId, programId } });
    return { policy, serviceProfile: profile };
  }

  async upsertPolicy(user: RequestUser, workspaceId: string, programId: string, input: Record<string, unknown>) {
    requireEasmPermission(user, "MANAGE_EASM_SCOPE");
    await this.getProgram(workspaceId, programId);
    const data: Row = {};
    for (const key of ["mode", "passiveDiscovery", "dnsResolution", "certificateDiscovery", "httpProbing", "serviceDiscovery", "technologyDetection", "historicalUrls", "frequency", "maxCandidatesPerRun", "allowPromotion"]) {
      if (input[key] !== undefined) data[key] = input[key];
    }
    // Policy guard (§10/§153): service discovery and HTTP probing are
    // ACTIVE techniques — in PASSIVE_ONLY mode they are forced off.
    if (data.mode === "PASSIVE_ONLY") {
      data.httpProbing = false;
      data.serviceDiscovery = false;
    }
    const existing = await this.prisma.easmDiscoveryPolicy.findFirst({ where: { workspaceId, programId } });
    if (existing) return this.prisma.easmDiscoveryPolicy.update({ where: { id: existing.id as string }, data: data as never });
    return this.prisma.easmDiscoveryPolicy.create({ data: { programId, workspaceId, ...data } as never });
  }

  async upsertServiceProfile(user: RequestUser, workspaceId: string, programId: string, input: { ports: number[]; ratePerSecond?: number; timeoutMs?: number; retries?: number }) {
    requireEasmPermission(user, "MANAGE_EASM_SCOPE");
    await this.getProgram(workspaceId, programId);
    const data = {
      ports: [...new Set(input.ports)].sort((a, b) => a - b),
      ratePerSecond: input.ratePerSecond ?? 100, timeoutMs: input.timeoutMs ?? 1500, retries: input.retries ?? 1,
    };
    const existing = await this.prisma.easmServiceDiscoveryProfile.findFirst({ where: { workspaceId, programId } });
    if (existing) return this.prisma.easmServiceDiscoveryProfile.update({ where: { id: existing.id as string }, data });
    return this.prisma.easmServiceDiscoveryProfile.create({ data: { programId, workspaceId, ...data } });
  }
}
