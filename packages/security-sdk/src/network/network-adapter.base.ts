import type { NormalizedSecurityResult } from "../findings/finding.types";
import { ReconAdapterBase } from "../recon/recon-adapter.base";
import type { ParsedNetwork, NetworkParser } from "./parsers-network";

/**
 * Base for the Prompt 10 network adapters. Same lifecycle and ToolRunner
 * boundary as the recon/vuln adapters — the difference is normalize():
 * network parsers produce assets + services + governed findings +
 * exposure observations + (for offline analysis) transactions/captures.
 * Findings exist only when the governed check policy created them from
 * real parser output (§37) — never from an open port alone.
 */
export abstract class NetworkAdapterBase extends ReconAdapterBase {
  protected abstract override readonly parser: NetworkParser;

  async parse(raw: string): Promise<unknown> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    const parsed = this.parser.parse(text);
    this.lastWarnings = parsed.warnings;
    return parsed;
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedNetwork;
    return {
      assets: p.assets ?? [],
      services: p.services ?? [],
      endpoints: [],
      technologies: [],
      findings: p.findings ?? [],
      ...(p.transactions?.length ? { transactions: p.transactions } : {}),
      ...(p.captures?.length ? { packetCaptures: p.captures } : {}),
      artifacts: [],
      metrics: {
        ...(p.metrics ?? {}),
        observations: (p.observations ?? []).length,
        exposures: (p.exposures ?? []).length,
        parserWarnings: (p.warnings ?? []).length,
        ...(this.lastOutcome ? { outcomePartial: this.lastOutcome === "PARTIAL" ? 1 : 0 } : {}),
      },
      mock: false,
    };
  }
}
