import { describe, expect, it } from "vitest";
import { JsonSecurityParser } from "./parser.interface";
import { JsonlSecurityParser } from "./jsonl.parser";
import { XmlSecurityParser } from "./xml.parser";
import { ParserError } from "../adapter/adapter.errors";

describe("parsers", () => {
  it("JSON parser validates and parses, and rejects garbage", async () => {
    const p = new JsonSecurityParser();
    expect(await p.validate('{"findings":[]}')).toBe(true);
    expect(await p.validate("not json")).toBe(false);
    const r = await p.parse('{"metrics":{"a":1}}');
    expect(r.metrics.a).toBe(1);
  });
  it("JSONL parser merges per-line records and errors with line numbers", async () => {
    const p = new JsonlSecurityParser();
    const out = '{"findings":[{"title":"a","description":"","severity":"LOW","confidence":1,"references":[],"sourceTool":"t","sourceFingerprint":"f"}]}\n{"assets":[{"host":"h","type":"domain"}]}';
    const r = await p.parse(out);
    expect(r.findings).toHaveLength(1);
    expect(r.assets).toHaveLength(1);
    expect(r.metrics.records).toBe(2);
    await expect(p.parse('{"ok":1}\nnot-json')).rejects.toBeInstanceOf(ParserError);
  });
  it("XML parser extracts findings and throws ParserError on malformed input", async () => {
    const p = new XmlSecurityParser();
    const xml = "<report><finding><title>Weak TLS</title><severity>HIGH</severity><host>example.com</host><cwe>CWE-327</cwe></finding></report>";
    const r = await p.parse(xml);
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.severity).toBe("HIGH");
    expect(r.findings[0]!.cwe).toBe("CWE-327");
    await expect(p.parse("plain text, no xml")).rejects.toBeInstanceOf(ParserError);
    expect(await p.validate("<report></report>")).toBe(true);
  });
});
