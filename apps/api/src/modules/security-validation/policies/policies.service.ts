import { Inject, Injectable } from "@nestjs/common";
import {
  ADMIN_HARD_LIMITS,
  DEFAULT_VALIDATION_BUDGET,
  clampValidationBudget,
  type OrganizationValidationPolicy,
  type ValidationBudget,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";

/**
 * Workspace validation policy (Prompt 16 §64/§77). One row per
 * workspace; when no row exists the shipped defaults apply — production
 * SAFE_ONLY (§64), separation of duties on (§11), intrusive-in-lab off
 * (§63). Administrator hard limits (§41) are clamped to the platform
 * ceiling: a workspace admin can tighten, never widen past ADMIN
 * limits.
 */
export interface ValidationPolicyView extends OrganizationValidationPolicy {
  workspaceId: string;
  defaultBudget: ValidationBudget;
  hardLimits: ValidationBudget;
  defaultTimeoutSeconds: number;
  approvalTtlMinutes: number;
  evidenceRetentionDays: number;
  callbackEnabled: boolean;
  defaultRiskLevel: string;
}

@Injectable()
export class ValidationPoliciesService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async getPolicy(workspaceId: string): Promise<ValidationPolicyView> {
    const row = await this.prisma.validationPolicy.findUnique({ where: { workspaceId } });
    if (!row) {
      return {
        workspaceId,
        productionPolicy: "SAFE_ONLY",
        separationOfDuties: true,
        allowIntrusiveInLab: false,
        allowedValidators: [],
        defaultBudget: { ...DEFAULT_VALIDATION_BUDGET },
        hardLimits: { ...ADMIN_HARD_LIMITS },
        defaultTimeoutSeconds: 300,
        approvalTtlMinutes: 60,
        evidenceRetentionDays: 365,
        callbackEnabled: false,
        defaultRiskLevel: "SAFE",
      };
    }
    return {
      workspaceId,
      productionPolicy: row.productionPolicy === "SAFE_AND_LOW_IMPACT_WITH_APPROVAL" ? "SAFE_AND_LOW_IMPACT_WITH_APPROVAL" : "SAFE_ONLY",
      separationOfDuties: row.separationOfDuties,
      allowIntrusiveInLab: row.allowIntrusiveInLab,
      allowedValidators: row.allowedValidators,
      defaultBudget: clampValidationBudget((row.defaultBudget ?? {}) as Partial<ValidationBudget>, DEFAULT_VALIDATION_BUDGET, ADMIN_HARD_LIMITS),
      hardLimits: clampValidationBudget((row.hardLimits ?? {}) as Partial<ValidationBudget>, ADMIN_HARD_LIMITS, ADMIN_HARD_LIMITS),
      defaultTimeoutSeconds: row.defaultTimeoutSeconds,
      approvalTtlMinutes: row.approvalTtlMinutes,
      evidenceRetentionDays: row.evidenceRetentionDays,
      callbackEnabled: row.callbackEnabled,
      defaultRiskLevel: row.defaultRiskLevel,
    };
  }

  /** The engine-facing policy (§7 input) for a workspace. */
  async enginePolicy(workspaceId: string): Promise<OrganizationValidationPolicy> {
    const view = await this.getPolicy(workspaceId);
    return {
      productionPolicy: view.productionPolicy,
      separationOfDuties: view.separationOfDuties,
      allowIntrusiveInLab: view.allowIntrusiveInLab,
      allowedValidators: view.allowedValidators,
    };
  }

  async updatePolicy(user: RequestUser, workspaceId: string, input: {
    productionPolicy?: string;
    defaultRiskLevel?: string;
    separationOfDuties?: boolean;
    allowIntrusiveInLab?: boolean;
    allowedValidators?: string[];
    hardLimits?: Partial<ValidationBudget>;
    defaultBudget?: Partial<ValidationBudget>;
    defaultTimeoutSeconds?: number;
    approvalTtlMinutes?: number;
    evidenceRetentionDays?: number;
    callbackEnabled?: boolean;
  }): Promise<ValidationPolicyView> {
    requireValidationPermission(user, "MANAGE_VALIDATION_POLICY");
    const hardLimits = clampValidationBudget(input.hardLimits ?? {}, ADMIN_HARD_LIMITS, ADMIN_HARD_LIMITS);
    const defaultBudget = clampValidationBudget(input.defaultBudget ?? {}, DEFAULT_VALIDATION_BUDGET, hardLimits);
    const data = {
      productionPolicy: input.productionPolicy === "SAFE_AND_LOW_IMPACT_WITH_APPROVAL" ? "SAFE_AND_LOW_IMPACT_WITH_APPROVAL" : "SAFE_ONLY",
      ...(input.defaultRiskLevel ? { defaultRiskLevel: input.defaultRiskLevel } : {}),
      ...(input.separationOfDuties !== undefined ? { separationOfDuties: input.separationOfDuties } : {}),
      ...(input.allowIntrusiveInLab !== undefined ? { allowIntrusiveInLab: input.allowIntrusiveInLab } : {}),
      ...(input.allowedValidators ? { allowedValidators: input.allowedValidators } : {}),
      hardLimits: hardLimits as never,
      defaultBudget: defaultBudget as never,
      ...(input.defaultTimeoutSeconds ? { defaultTimeoutSeconds: Math.min(Math.max(30, input.defaultTimeoutSeconds), ADMIN_HARD_LIMITS.maxDurationSeconds) } : {}),
      ...(input.approvalTtlMinutes ? { approvalTtlMinutes: Math.min(Math.max(5, input.approvalTtlMinutes), 24 * 60) } : {}),
      ...(input.evidenceRetentionDays ? { evidenceRetentionDays: input.evidenceRetentionDays } : {}),
      ...(input.callbackEnabled !== undefined ? { callbackEnabled: input.callbackEnabled } : {}),
      updatedBy: user.id,
    };
    await this.prisma.validationPolicy.upsert({
      where: { workspaceId },
      create: { workspaceId, ...data },
      update: data,
    });
    return this.getPolicy(workspaceId);
  }
}
