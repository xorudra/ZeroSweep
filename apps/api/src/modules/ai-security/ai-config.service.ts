import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import type { AiProviderDataPolicy, AiTaskType, AiWorkspaceAccessPolicy } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { requireAiPermission } from "./permissions";

/**
 * AI provider/model/policy administration (Prompt 21 §4/§64/§104/§109/
 * §110). Credentials are secret REFERENCES only: the API accepts and
 * stores a reference NAME, and no response ever includes it — admin
 * views expose `credentialConfigured: boolean` (§110).
 */
@Injectable()
export class AiConfigService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /** §109 defaults materialized lazily — spec defaults (§16/§17/§104). */
  async getPolicy(workspaceId: string): Promise<AiWorkspaceAccessPolicy & { primaryModelId?: string | null; fallbackModelId?: string | null }> {
    const row = await this.prisma.aiWorkspacePolicy.findFirst({ where: { workspaceId } });
    if (!row) {
      return { sourceCodeAccess: "REDACTED", rawEvidenceAccess: "SANITIZED_ONLY", enabledTasks: [], primaryModelId: null, fallbackModelId: null };
    }
    return {
      sourceCodeAccess: row.sourceCodeAccess as AiWorkspaceAccessPolicy["sourceCodeAccess"],
      rawEvidenceAccess: row.rawEvidenceAccess as AiWorkspaceAccessPolicy["rawEvidenceAccess"],
      enabledTasks: row.enabledTasks as AiTaskType[],
      primaryModelId: row.primaryModelId,
      fallbackModelId: row.fallbackModelId,
    };
  }

  async getBudget(workspaceId: string) {
    const row = await this.prisma.aiUsageBudget.findFirst({ where: { workspaceId } });
    return row ?? { dailyTokenLimit: 200000, monthlyTokenLimit: 4000000, perTaskTokenLimit: 16000, maxRetrievalRecords: 25 };
  }

  async updatePolicy(user: RequestUser, workspaceId: string, patch: Record<string, unknown>) {
    requireAiPermission(user, "MANAGE_AI_POLICY");
    const existing = await this.prisma.aiWorkspacePolicy.findFirst({ where: { workspaceId } });
    const data = {
      workspaceId,
      sourceCodeAccess: (patch.sourceCodeAccess as string) ?? existing?.sourceCodeAccess ?? "REDACTED",
      rawEvidenceAccess: (patch.rawEvidenceAccess as string) ?? existing?.rawEvidenceAccess ?? "SANITIZED_ONLY",
      enabledTasks: (patch.enabledTasks as string[]) ?? existing?.enabledTasks ?? [],
      chatRetentionDays: (patch.chatRetentionDays as number) ?? existing?.chatRetentionDays ?? 30,
      primaryModelId: (patch.primaryModelId as string | null) ?? existing?.primaryModelId ?? null,
      fallbackModelId: (patch.fallbackModelId as string | null) ?? existing?.fallbackModelId ?? null,
      // Prompt 36 §139 V2 settings (additive; §140 hard safety
      // controls are not patchable through settings by design).
      allowedModelIds: (patch.allowedModelIds as string[]) ?? existing?.allowedModelIds ?? [],
      dataResidencyRegion: (patch.dataResidencyRegion as string | null) ?? existing?.dataResidencyRegion ?? null,
      allowExternalProviders: (patch.allowExternalProviders as boolean) ?? existing?.allowExternalProviders ?? true,
      approvalPolicy: (patch.approvalPolicy as string) ?? existing?.approvalPolicy ?? "SOD_RESTRICTED",
      retentionTraceDays: (patch.retentionTraceDays as number) ?? existing?.retentionTraceDays ?? 90,
      retentionEvaluationDays: (patch.retentionEvaluationDays as number) ?? existing?.retentionEvaluationDays ?? 365,
    };
    const row = existing
      ? await this.prisma.aiWorkspacePolicy.update({ where: { id: existing.id }, data })
      : await this.prisma.aiWorkspacePolicy.create({ data });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_MODEL_CHANGED", resourceType: "AiWorkspacePolicy", resourceId: row.id, metadata: { fields: Object.keys(patch) } });
    return row;
  }

  async updateBudget(user: RequestUser, workspaceId: string, patch: Record<string, unknown>) {
    requireAiPermission(user, "MANAGE_AI_POLICY");
    const existing = await this.prisma.aiUsageBudget.findFirst({ where: { workspaceId } });
    const data = {
      workspaceId,
      dailyTokenLimit: (patch.dailyTokenLimit as number) ?? existing?.dailyTokenLimit ?? 200000,
      monthlyTokenLimit: (patch.monthlyTokenLimit as number) ?? existing?.monthlyTokenLimit ?? 4000000,
      perTaskTokenLimit: (patch.perTaskTokenLimit as number) ?? existing?.perTaskTokenLimit ?? 16000,
      maxRetrievalRecords: (patch.maxRetrievalRecords as number) ?? existing?.maxRetrievalRecords ?? 25,
    };
    const row = existing
      ? await this.prisma.aiUsageBudget.update({ where: { id: existing.id }, data })
      : await this.prisma.aiUsageBudget.create({ data });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_MODEL_CHANGED", resourceType: "AiUsageBudget", resourceId: row.id, metadata: { fields: Object.keys(patch) } });
    return row;
  }

  private providerView(row: Record<string, unknown>) {
    const { credentialRef, ...rest } = row;
    return { ...rest, credentialConfigured: !!credentialRef };
  }

  async listProviders(workspaceId: string) {
    const rows = await this.prisma.aiProviderConfig.findMany({ where: { workspaceId }, orderBy: { createdAt: "asc" } });
    return rows.map((r) => this.providerView(r as never));
  }

  async createProvider(user: RequestUser, workspaceId: string, body: Record<string, unknown>) {
    requireAiPermission(user, "MANAGE_AI_PROVIDERS");
    const row = await this.prisma.aiProviderConfig.create({
      data: {
        workspaceId,
        name: String(body.name ?? "provider"),
        providerType: String(body.providerType ?? "OPENAI_COMPATIBLE"),
        baseUrl: (body.baseUrl as string) ?? null,
        credentialRef: (body.credentialRef as string) ?? null, // reference NAME only (§64)
        isExternal: body.providerType === "LOCAL" || body.providerType === "MOCK" ? false : true,
        region: (body.region as string) ?? null,
        enabled: body.enabled === true,
        approvedClassifications: (body.approvedClassifications as string[]) ?? ["PUBLIC", "INTERNAL"],
        sourceCodeAllowance: (body.sourceCodeAllowance as string) ?? "REDACTED",
        retentionPolicy: (body.retentionPolicy as string) ?? null,
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_PROVIDER_CHANGED", resourceType: "AiProviderConfig", resourceId: row.id, metadata: { name: row.name, providerType: row.providerType } });
    return this.providerView(row as never);
  }

  async updateProvider(user: RequestUser, workspaceId: string, id: string, patch: Record<string, unknown>) {
    requireAiPermission(user, "MANAGE_AI_PROVIDERS");
    const existing = await this.prisma.aiProviderConfig.findFirst({ where: { id, workspaceId } });
    if (!existing) throw new NotFoundException("provider not found in this workspace");
    const row = await this.prisma.aiProviderConfig.update({ where: { id }, data: patch as never });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_PROVIDER_CHANGED", resourceType: "AiProviderConfig", resourceId: id, metadata: { fields: Object.keys(patch) } });
    return this.providerView(row as never);
  }

  async listModels(workspaceId: string) {
    return this.prisma.aiModel.findMany({ where: { workspaceId }, orderBy: { createdAt: "asc" } });
  }

  async createModel(user: RequestUser, workspaceId: string, body: Record<string, unknown>) {
    requireAiPermission(user, "MANAGE_AI_PROVIDERS");
    const provider = await this.prisma.aiProviderConfig.findFirst({ where: { id: String(body.providerId ?? ""), workspaceId } });
    if (!provider) throw new NotFoundException("provider not found in this workspace");
    const row = await this.prisma.aiModel.create({
      data: {
        workspaceId,
        providerId: provider.id,
        modelName: String(body.modelName ?? "model"),
        capabilities: (body.capabilities as string[]) ?? ["GENERATE"],
        contextLimit: (body.contextLimit as number) ?? 8192,
        enabled: body.enabled !== false,
        allowedTasks: (body.allowedTasks as string[]) ?? [],
        costMetadata: (body.costMetadata as object) ?? undefined,
        // Prompt 36 §4: V2 capability / cost / latency tracking.
        structuredOutputSupport: body.structuredOutputSupport === true,
        toolCallingSupport: body.toolCallingSupport === true,
        embeddingSupport: body.embeddingSupport === true,
        costClass: (body.costClass as string) ?? "LOW",
        latencyClass: (body.latencyClass as string) ?? "STANDARD",
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_MODEL_CHANGED", resourceType: "AiModel", resourceId: row.id, metadata: { modelName: row.modelName } });
    return row;
  }

  /** Resolve the runtime provider for a task: policy primary model →
   *  first enabled model of an enabled provider. Returns the SDK data
   *  policy view + model name; the transport itself is constructed by
   *  the copilot service (MOCK in-process; external transports are not
   *  provisioned in this build and report honestly). */
  async resolveProvider(workspaceId: string, policy: AiWorkspaceAccessPolicy & { primaryModelId?: string | null; fallbackModelId?: string | null }) {
    const providers = await this.prisma.aiProviderConfig.findMany({ where: { workspaceId, enabled: true } });
    if (providers.length === 0) return null;
    const models = await this.prisma.aiModel.findMany({ where: { workspaceId, enabled: true } });
    const pick = (modelId?: string | null) => {
      const model = modelId ? models.find((m) => m.id === modelId) : undefined;
      const m = model ?? models[0];
      if (!m) return null;
      const provider = providers.find((p) => p.id === m.providerId);
      if (!provider) return null;
      const dataPolicy: AiProviderDataPolicy = {
        providerName: provider.name,
        providerType: provider.providerType,
        isExternal: provider.isExternal,
        approvedClassifications: provider.approvedClassifications as AiProviderDataPolicy["approvedClassifications"],
        sourceCodeAllowance: provider.sourceCodeAllowance as AiProviderDataPolicy["sourceCodeAllowance"],
        enabled: provider.enabled,
      };
      return { providerRow: provider, modelRow: m, dataPolicy, modelName: m.modelName };
    };
    const primary = pick(policy.primaryModelId);
    if (!primary) return null;
    const fallback = policy.fallbackModelId && policy.fallbackModelId !== primary.modelRow.id ? pick(policy.fallbackModelId) : null;
    return { primary, fallback };
  }

  /** Prompt 36 §4/§5: V2 model capability records for the router —
   *  built from the same registry rows; health stays honest:
   *  non-MOCK transports in this build are NOT_CONFIGURED (§110). */
  async listModelCapabilities(workspaceId: string) {
    const [providers, models] = await Promise.all([
      this.prisma.aiProviderConfig.findMany({ where: { workspaceId } }),
      this.prisma.aiModel.findMany({ where: { workspaceId } }),
    ]);
    return models.map((m) => {
      const p = providers.find((x) => x.id === m.providerId);
      const transportProvisioned = p?.providerType === "MOCK";
      return {
        modelId: m.id,
        providerName: p?.name ?? "unknown",
        providerType: p?.providerType ?? "NONE",
        modelName: m.modelName,
        contextWindow: m.contextLimit,
        structuredOutputSupport: m.structuredOutputSupport ?? false,
        toolCallingSupport: m.toolCallingSupport ?? false,
        embeddingSupport: m.embeddingSupport ?? (m.capabilities?.includes("EMBED") ?? false),
        generateSupport: m.capabilities?.includes("GENERATE") ?? true,
        availability: !p?.enabled || !m.enabled ? "UNAVAILABLE" as const
          : transportProvisioned ? (m.healthStatus === "UNAVAILABLE" ? "UNAVAILABLE" as const : "AVAILABLE" as const)
          : "NOT_CONFIGURED" as const,
        costClass: (m.costClass ?? "LOW") as "FREE" | "LOW" | "MEDIUM" | "HIGH",
        latencyClass: (m.latencyClass ?? "STANDARD") as "FAST" | "STANDARD" | "SLOW",
        isExternal: p?.isExternal ?? true,
        region: p?.region ?? null,
        approvedClassifications: (p?.approvedClassifications ?? ["PUBLIC", "INTERNAL"]) as never,
        enabled: !!p?.enabled && m.enabled,
      };
    });
  }

  /** Prompt 36 §5/§6/§139: the tenant routing policy for a workspace. */
  async getRoutingPolicy(workspaceId: string) {
    const row = await this.prisma.aiWorkspacePolicy.findFirst({ where: { workspaceId } });
    return {
      allowedModelIds: row?.allowedModelIds ?? [],
      dataResidencyRegion: row?.dataResidencyRegion ?? null,
      allowExternalProviders: row?.allowExternalProviders ?? true,
      approvalPolicy: row?.approvalPolicy ?? "SOD_RESTRICTED",
      maxCostClass: undefined as undefined | "FREE" | "LOW" | "MEDIUM" | "HIGH",
      preferredModelId: row?.primaryModelId ?? null,
    };
  }

  /** §110 provider health — statuses only, never credentials. */
  async providerHealth(workspaceId: string) {
    const providers = await this.prisma.aiProviderConfig.findMany({ where: { workspaceId } });
    const models = await this.prisma.aiModel.findMany({ where: { workspaceId } });
    return providers.map((p) => ({
      provider: p.name,
      type: p.providerType,
      // Only the in-process MOCK transport is provisioned in this
      // build; external/LOCAL transports report NOT_CONFIGURED rather
      // than faking a healthy probe (§110/§103).
      status: !p.enabled ? "DISABLED" : p.providerType === "MOCK" ? "HEALTHY" : "NOT_CONFIGURED",
      latencyMs: p.providerType === "MOCK" && p.enabled ? 1 : null,
      lastSuccessfulAt: p.lastSuccessfulAt,
      capabilities: models.filter((m) => m.providerId === p.id).flatMap((m) => m.capabilities),
      models: models.filter((m) => m.providerId === p.id).map((m) => ({ modelName: m.modelName, enabled: m.enabled, contextLimit: m.contextLimit, healthStatus: m.healthStatus })),
    }));
  }
}
