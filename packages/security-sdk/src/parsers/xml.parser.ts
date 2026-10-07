import { ParserError } from "../adapter/adapter.errors";
import type { NormalizedFinding, NormalizedSecurityResult } from "../findings/finding.types";
import type { SecurityToolParser } from "./parser.interface";

/**
 * Minimal, dependency-free XML parser for scanner reports shaped as
 * <report><finding><title>..</title><severity>..</severity>..</finding></report>.
 * It intentionally supports only the record extraction the SDK needs —
 * general XML/XPath processing belongs to per-adapter parsers in later
 * phases. Malformed input throws ParserError, never a raw exception.
 */
export class XmlSecurityParser implements SecurityToolParser {
  readonly format = "XML";
  async validate(output: string): Promise<boolean> {
    try { this.extractFindings(output); return true; } catch { return false; }
  }
  async parse(output: string): Promise<NormalizedSecurityResult> {
    const findings = this.extractFindings(output);
    return {
      assets: [], services: [], endpoints: [], technologies: [], findings, artifacts: [],
      metrics: { records: findings.length }, mock: false,
    };
  }
  private extractFindings(output: string): NormalizedFinding[] {
    const xml = output.trim();
    if (!xml.startsWith("<")) throw new ParserError("XML output must start with an element");
    if (!/<\/?[a-zA-Z][^>]*>/.test(xml)) throw new ParserError("No XML elements found");
    const blocks = [...xml.matchAll(/<finding>([\s\S]*?)<\/finding>/g)];
    return blocks.map((b) => {
      const body = b[1]!;
      const field = (name: string): string | undefined => {
        const m = body.match(new RegExp(`<${name}>([\\s\\S]*?)</${name}>`));
        return m ? decodeXml(m[1]!.trim()) : undefined;
      };
      const title = field("title");
      if (!title) throw new ParserError("XML finding is missing <title>");
      const severityRaw = (field("severity") ?? "INFORMATIONAL").toUpperCase();
      const severity = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].includes(severityRaw) ? severityRaw : "INFORMATIONAL") as NormalizedFinding["severity"];
      return {
        title, description: field("description") ?? "", severity,
        confidence: Number(field("confidence") ?? 0.5),
        host: field("host"), port: field("port") ? Number(field("port")) : undefined,
        endpoint: field("endpoint"), cve: field("cve"), cwe: field("cwe"),
        remediation: field("remediation"), references: [],
        sourceTool: field("sourceTool") ?? "xml-import", sourceFingerprint: field("fingerprint") ?? "",
      };
    });
  }
}

export function decodeXml(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}
