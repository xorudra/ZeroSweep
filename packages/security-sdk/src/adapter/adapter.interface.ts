import type { TargetType } from "@dsrclone/types";
import type { ToolMetadata } from "./adapter.types";
import type { AuthorizationContext, ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";

export interface AdapterTarget { type: TargetType; value: string; host: string; }

/** Every future tool adapter implements this lifecycle. The orchestrator only
 *  ever talks to adapters through this contract. */
export interface SecurityToolAdapter {
  readonly metadata: ToolMetadata;
  validateConfiguration(config: Record<string, unknown>): Promise<void>;
  validateTarget(target: AdapterTarget): Promise<void>;
  validateScope(target: AdapterTarget): Promise<void>;
  checkAvailability(): Promise<boolean>;
  prepare(ctx: AuthorizationContext): Promise<void>;
  buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan>;
  /** Interface/mock only in this phase — real execution lands in later phases. */
  execute(plan: ExecutionPlan): Promise<{ rawOutputLocation?: string }>;
  parse(raw: string): Promise<unknown>;
  normalize(parsed: unknown): Promise<NormalizedSecurityResult>;
  cleanup(): Promise<void>;
  healthCheck(): Promise<{ status: string; detail?: string }>;
}
