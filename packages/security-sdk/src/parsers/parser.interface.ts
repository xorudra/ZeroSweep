import type { NormalizedSecurityResult } from "../findings/finding.types";

/** Parsing is separate from execution. */
export interface SecurityToolParser {
  readonly format: string;
  validate(output: string): Promise<boolean>;
  parse(output: string): Promise<NormalizedSecurityResult>;
}

export class JsonSecurityParser implements SecurityToolParser {
  readonly format = "JSON";
  async validate(output: string): Promise<boolean> {
    try { JSON.parse(output); return true; } catch { return false; }
  }
  async parse(output: string): Promise<NormalizedSecurityResult> {
    const parsed = JSON.parse(output) as Partial<NormalizedSecurityResult>;
    return {
      assets: parsed.assets ?? [], services: parsed.services ?? [], endpoints: parsed.endpoints ?? [],
      technologies: parsed.technologies ?? [], findings: parsed.findings ?? [], artifacts: parsed.artifacts ?? [],
      metrics: parsed.metrics ?? {}, mock: parsed.mock ?? false,
    };
  }
}
