import { AdapterConfigurationError, UnsupportedTargetError } from "./adapter.errors";
import { FORBIDDEN_INPUT_FIELDS } from "./adapter.types";
import { assertValidTarget } from "../targets/target.validation";
import type { AdapterTarget, SecurityToolAdapter } from "./adapter.interface";
import type { ToolMetadata } from "./adapter.types";
import type { AuthorizationContext, ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";

export abstract class BaseSecurityToolAdapter implements SecurityToolAdapter {
  abstract readonly metadata: ToolMetadata;

  /**
   * Configuration is validated against the adapter's declared input schema
   * (Prompt 3 §8). Unknown keys are rejected, required keys enforced, and a
   * raw "command"-style key is always an error — adapters never accept one.
   */
  async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    for (const key of Object.keys(config)) {
      if (FORBIDDEN_INPUT_FIELDS.includes(key as never)) {
        throw new AdapterConfigurationError(`Configuration key "${key}" is forbidden: adapters never accept raw commands`);
      }
    }
    const schema = this.metadata.inputSchema ?? [];
    if (schema.length === 0) return;
    const declared = new Set(schema.map((f) => f.name));
    for (const key of Object.keys(config)) {
      if (!declared.has(key)) throw new AdapterConfigurationError(`Unknown configuration key for ${this.metadata.slug}: ${key}`);
    }
    for (const field of schema) {
      const v = config[field.name];
      if (v === undefined) {
        if (field.required) throw new AdapterConfigurationError(`Missing required configuration: ${field.name}`);
        continue;
      }
      const ok =
        field.type === "string" ? typeof v === "string"
        : field.type === "number" ? typeof v === "number" && Number.isFinite(v)
        : field.type === "boolean" ? typeof v === "boolean"
        : field.type === "string[]" ? Array.isArray(v) && v.every((x) => typeof x === "string")
        : Array.isArray(v) && v.every((x) => typeof x === "number");
      if (!ok) throw new AdapterConfigurationError(`Configuration ${field.name} must be of type ${field.type}`);
      if (field.type === "number") {
        if (field.min !== undefined && (v as number) < field.min) throw new AdapterConfigurationError(`${field.name} is below minimum ${field.min}`);
        if (field.max !== undefined && (v as number) > field.max) throw new AdapterConfigurationError(`${field.name} exceeds maximum ${field.max}`);
      }
      if (field.enumValues && typeof v === "string" && !field.enumValues.includes(v)) {
        throw new AdapterConfigurationError(`${field.name} must be one of: ${field.enumValues.join(", ")}`);
      }
    }
  }
  async validateTarget(target: AdapterTarget): Promise<void> {
    if (!this.metadata.supportedTargetTypes.includes(target.type)) {
      throw new UnsupportedTargetError(`${this.metadata.slug} does not support target type ${target.type}`);
    }
    // Host-based target types also pass the SSRF / format gate (Prompt 3 §14).
    if (["DOMAIN", "WEB_APPLICATION", "IP_ADDRESS", "CIDR", "API", "GRAPHQL"].includes(target.type)) {
      assertValidTarget(target.value);
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
