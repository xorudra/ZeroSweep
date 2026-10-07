import type { NormalizedSecurityResult } from "../findings/finding.types";
import { ReconAdapterBase } from "../recon/recon-adapter.base";
import type { ParsedVuln, VulnParser } from "./parsers-vuln";

/**
 * Base for the Prompt 7 vulnerability/TLS adapters. Same lifecycle and
 * ToolRunner boundary as the recon adapters (§2) — the difference is only
 * in normalize(): parsers here produce FINDINGS (through ParsedVuln), while
 * recon parsers never do. Findings exist only when the tool output
 * actually contains them.
 */
export abstract class VulnAdapterBase extends ReconAdapterBase {
  protected abstract override readonly parser: VulnParser;

  async parse(raw: string): Promise<unknown> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    const parsed = this.parser.parse(text);
    this.lastWarnings = parsed.warnings;
    return parsed;
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedVuln;
    return {
      assets: [],
      services: p.services ?? [],
      endpoints: [],
      technologies: [],
      findings: p.findings ?? [],
      artifacts: [],
      metrics: {
        ...(p.metrics ?? {}),
        observations: (p.observations ?? []).length,
        parserWarnings: (p.warnings ?? []).length,
        ...(this.lastOutcome ? { outcomePartial: this.lastOutcome === "PARTIAL" ? 1 : 0 } : {}),
      },
      mock: false,
    };
  }
}
