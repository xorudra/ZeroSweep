import type { AssessmentProfile, TargetType } from "@dsrclone/types";
import type { ScopeRules } from "@dsrclone/validation";
import type { ToolRegistry } from "@dsrclone/security-sdk";
import { buildDag, type ValidatedDag } from "./dag";
import { resolveTemplate, type StageType } from "./profiles";
import { selectAdaptersForStage, type SelectedAdapter, type ToolSelectionOptions } from "./tool-selector";
import type { StageStatus } from "./state-machines";

/**
 * ScanPlan (Prompt 4 §4) — the immutable contract between planning and
 * execution. Once a scan starts, the plan's stages/dependencies/selection do
 * not change; only state/progress fields move.
 */

export interface PlannedStage {
  id: string; // == type
  type: StageType;
  name: string;
  description: string;
  requiredCapabilities: string[];
  /** Prompt 7 §14/§50: any-of capability groups + per-profile allowlist,
   *  recorded on the plan so the executed selection is auditable. */
  capabilityGroups?: string[][];
  adapterAllowlist?: string[];
  dependencies: StageType[];
  selectedAdapters: SelectedAdapter[];
  weight: number;
  timeoutSeconds: number;
  failureStrategy: string;
  networkCapable: boolean;
  status: StageStatus;
}

export interface ScanPlan {
  scanId: string;
  assessmentId: string;
  targetId: string;
  workspaceId: string;
  organizationId: string;
  profile: AssessmentProfile;
  targetType: TargetType;
  targetValue: string;
  targetHost: string;
  scope: ScopeRules;
  stages: PlannedStage[];
  dependencies: Record<string, string[]>;
  selectedTools: string[];
  /** Frozen inputs the policy engine was evaluated with (no secrets). */
  policySnapshot: {
    targetVerified: boolean;
    assessmentApproved: boolean;
    executableSlugs: string[];
    simulation: boolean;
  };
  planVersion: number;
  createdAt: string;
}

export interface BuildScanPlanInput {
  scanId: string;
  assessmentId: string;
  targetId: string;
  workspaceId: string;
  organizationId: string;
  profile: AssessmentProfile;
  targetType: TargetType;
  targetValue: string;
  targetHost: string;
  scope: ScopeRules;
  targetVerified: boolean;
  assessmentApproved: boolean;
  registry: ToolRegistry;
  selection: Omit<ToolSelectionOptions, "targetType">;
  createdAt?: Date;
}

/** Stages executed by the orchestration engine itself — never by a tool. */
export const PLATFORM_STAGE_TYPES = new Set([
  "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "NORMALIZATION",
  "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION", "WEB_SURFACE_NORMALIZATION",
  // Prompt 9: platform-executed API stages (discovery consolidation,
  // import summary, auth mapping, JWT inspection, WebSocket inventory,
  // API finding normalization) — the worker runs them as engine hooks.
  "API_DISCOVERY", "SPEC_IMPORT", "AUTH_MAPPING", "JWT_ANALYSIS",
  "WEBSOCKET_INVENTORY", "API_FINDING_NORMALIZATION",
  // Prompt 10: target expansion is computed by the engine/store hook
  // (bounded chunking, §5/§62) — no adapter executes for it.
  "TARGET_EXPANSION",
]);

export class InvalidPlanError extends Error {
  constructor(public readonly errors: string[]) {
    super(`Invalid scan plan: ${errors.join("; ")}`);
    this.name = "InvalidPlanError";
  }
}

export function buildScanPlan(input: BuildScanPlanInput): { plan: ScanPlan; dag: ValidatedDag } {
  const defs = resolveTemplate(input.profile);
  const { dag, errors } = buildDag(defs);
  if (!dag) throw new InvalidPlanError(errors.map((e) => e.message));

  const stages: PlannedStage[] = dag.nodes.map((node) => {
    // Platform stages are engine components, not tools (spec §2): they never
    // get an adapter selected — the runner executes them as in-process checks.
    const selection = PLATFORM_STAGE_TYPES.has(node.type)
      ? { selected: [] as SelectedAdapter[] }
      : selectAdaptersForStage(input.registry, node, {
          ...input.selection,
          targetType: input.targetType,
          ...(node.adapterLimit !== undefined ? { adapterLimit: node.adapterLimit } : {}),
        });
    return {
      id: node.id,
      type: node.type,
      name: node.name,
      description: node.description,
      requiredCapabilities: [...node.requiredCapabilities],
      ...(node.capabilityGroups ? { capabilityGroups: node.capabilityGroups.map((g) => [...g]) } : {}),
      ...(node.adapterAllowlist ? { adapterAllowlist: [...node.adapterAllowlist] } : {}),
      dependencies: [...node.dependencies],
      selectedAdapters: selection.selected,
      weight: node.weight,
      timeoutSeconds: node.timeoutSeconds,
      failureStrategy: node.failureStrategy,
      networkCapable: node.networkCapable,
      status: node.dependencies.length === 0 ? "READY" : "BLOCKED",
    };
  });

  const selectedTools = [...new Set(stages.flatMap((s) => s.selectedAdapters.map((a) => a.slug)))];
  const plan: ScanPlan = {
    scanId: input.scanId,
    assessmentId: input.assessmentId,
    targetId: input.targetId,
    workspaceId: input.workspaceId,
    organizationId: input.organizationId,
    profile: input.profile,
    targetType: input.targetType,
    targetValue: input.targetValue,
    targetHost: input.targetHost,
    scope: input.scope,
    stages,
    dependencies: Object.fromEntries(stages.map((s) => [s.id, s.dependencies])),
    selectedTools,
    policySnapshot: {
      targetVerified: input.targetVerified,
      assessmentApproved: input.assessmentApproved,
      executableSlugs: [...input.selection.executableSlugs],
      simulation: stages.some((s) => s.selectedAdapters.some((a) => a.simulation)),
    },
    planVersion: 1,
    createdAt: (input.createdAt ?? new Date()).toISOString(),
  };
  return { plan, dag };
}
