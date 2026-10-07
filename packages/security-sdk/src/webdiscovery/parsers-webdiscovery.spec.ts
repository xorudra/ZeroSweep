import { describe, expect, it } from "vitest";
import { ArjunParser, FeroxbusterParser, FfufParser, GobusterParser, WfuzzParser } from "./parsers-webdiscovery";
import { ARJUN_JSON, FEROX_JSONL, FFUF_JSON, GOBUSTER_TEXT, WFUZZ_CONTENT_JSON, WFUZZ_JSON } from "./fixtures";

describe("web-discovery parsers (§37–§38)", () => {
  it("ffuf JSON: endpoints carry response classification metadata + fingerprints", () => {
    const parsed = new FfufParser().parse(FFUF_JSON);
    expect(parsed.endpoints).toHaveLength(9);
    const admin = parsed.endpoints.find((e) => e.url.endsWith("/admin"))!;
    expect(admin).toMatchObject({ statusCode: 200, contentLength: 1234, contentType: "text/html; charset=utf-8", source: "ffuf" });
    expect(admin.fingerprint).toBeTruthy();
    const promo = parsed.endpoints.find((e) => e.url.endsWith("/promo"))!;
    expect(promo.redirectLocation).toBe("https://thirdparty.example.net/promo");
    expect(parsed.warnings).toEqual([]);
  });

  it("feroxbuster JSONL: only response records become endpoints; junk becomes warnings", () => {
    const parsed = new FeroxbusterParser().parse(FEROX_JSONL);
    expect(parsed.endpoints.map((e) => e.url)).toEqual([
      "https://example.com/admin/", "https://example.com/api", "https://example.com/uploads",
    ]);
    expect(parsed.endpoints[2]).toMatchObject({ statusCode: 403 });
    expect(parsed.warnings.some((w) => w.includes("non-JSON"))).toBe(true);
  });

  it("gobuster text: paths absolutize against the PLAN base; banner lines are ignored", () => {
    const parsed = new GobusterParser("https://example.com/").parse(GOBUSTER_TEXT);
    expect(parsed.endpoints.map((e) => `${e.url}|${e.statusCode}`)).toEqual([
      "https://example.com/admin|200",
      "https://example.com/images|301",
      "https://example.com/server-status|403",
    ]);
    expect(parsed.endpoints[1]!.redirectLocation).toBe("https://example.com/images/");
    // Without a base, paths cannot become endpoints — nothing is invented.
    expect(new GobusterParser().parse(GOBUSTER_TEXT).endpoints).toHaveLength(0);
  });

  it("wfuzz: content entries become endpoints; parameter template yields parameter NAMES", () => {
    const content = new WfuzzParser().parse(WFUZZ_CONTENT_JSON);
    expect(content.endpoints.map((e) => e.url)).toEqual(["https://example.com/admin", "https://example.com/backup"]);
    expect(content.parameters).toEqual([]);
    const params = new WfuzzParser().parse(WFUZZ_JSON);
    expect(params.parameters).toEqual(expect.arrayContaining([
      { endpointUrl: "https://example.com/search", name: "id", location: "QUERY", sources: ["wfuzz"], confidence: 0.8 },
      { endpointUrl: "https://example.com/search", name: "sort", location: "QUERY", sources: ["wfuzz"], confidence: 0.8 },
    ]));
  });

  it("arjun: parameter names per URL; values/details are ignored (§7)", () => {
    const parsed = new ArjunParser().parse(ARJUN_JSON);
    expect(parsed.parameters).toHaveLength(5);
    expect(parsed.parameters!.filter((p) => p.endpointUrl === "https://example.com/search").map((p) => p.name)).toEqual(["id", "page", "q"]);
    expect(parsed.endpoints.map((e) => e.url)).toContain("https://example.com/api/users");
  });

  it("malformed output degrades to warnings, never throws (§38)", () => {
    expect(new FfufParser().parse("{not json").warnings[0]).toMatch(/unsupported format/);
    expect(new FfufParser().parse('{"unexpected":true}').warnings[0]).toMatch(/no results array/);
    expect(new WfuzzParser().parse("[]").endpoints).toEqual([]);
    expect(new ArjunParser().parse("42").warnings[0]).toMatch(/unsupported shape/);
    expect(new ArjunParser().parse("").records).toBe(0);
  });
});
