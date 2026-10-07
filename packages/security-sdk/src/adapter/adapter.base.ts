import { UnsupportedTargetError } from "./adapter.errors";
import type { AdapterTarget, SecurityToolAdapter } from "./adapter.interface";
import type { ToolMetadata } from "./adapter.types";
import type { AuthorizationContext, ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";

export abstract class BaseSecurityToolAdapter implements SecurityToolAdapter {
  abstract readonly metadata: ToolMetadata;

  async validateConfiguration(_config: Record<string, unknown>): Promise<void> { /* per-adapter */ }
  async validateTarget(target: AdapterTarget): Promise<void> {
    if (!this.metadata.supportedTargetTypes.includes(target.type)) {
      throw new UnsupportedTargetError(`${this.metadata.slug} does not support target type ${target.type}`);
    }
  }
  async validateScope(_target: AdapterTarget): Promise<void> { /* scope matcher enforced by policy + worker */ }
  async checkAvailability(): Promise<boolean> { return false; }
  async prepare(_ctx: AuthorizationContext): Promise<void> { /* per-adapter */ }
  abstract buildExecutionPlan(target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan>;
  abstract execute(plan: ExecutionPlan): Promise<{ rawOutputLocation?: string }>;
  abstract parse(raw: string): Promise<unknown>;
  abstract normalize(parsed: unknown): Promise<NormalizedSecurityResult>;
  async cleanup(): Promise<void> { /* per-adapter */ }
  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: "Health check not implemented for this adapter yet" };
  }
}
