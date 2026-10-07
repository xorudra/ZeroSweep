import { ParserError } from "../adapter/adapter.errors";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import type { SecurityToolParser } from "./parser.interface";

const empty = (): NormalizedSecurityResult => ({
  assets: [], services: [], endpoints: [], technologies: [], findings: [], artifacts: [], metrics: {}, mock: false,
});

/** JSON Lines parser — one JSON record per line (Nuclei-style output shape). */
export class JsonlSecurityParser implements SecurityToolParser {
  readonly format = "JSONL";
  async validate(output: string): Promise<boolean> {
    try { this.records(output); return true; } catch { return false; }
  }
  async parse(output: string): Promise<NormalizedSecurityResult> {
    const result = empty();
    for (const rec of this.records(output)) {
      const r = rec as Partial<NormalizedSecurityResult> & { findings?: NormalizedSecurityResult["findings"] };
      if (Array.isArray(r.findings)) result.findings.push(...r.findings);
      if (Array.isArray(r.assets)) result.assets.push(...r.assets);
      if (Array.isArray(r.services)) result.services.push(...r.services);
      if (Array.isArray(r.endpoints)) result.endpoints.push(...r.endpoints);
      if (Array.isArray(r.technologies)) result.technologies.push(...r.technologies);
    }
    result.metrics = { records: this.records(output).length };
    return result;
  }
  private records(output: string): unknown[] {
    const lines = output.split("\n").map((l) => l.trim()).filter(Boolean);
    return lines.map((l, i) => {
      try { return JSON.parse(l); } catch { throw new ParserError(`Invalid JSONL at line ${i + 1}`); }
    });
  }
}
