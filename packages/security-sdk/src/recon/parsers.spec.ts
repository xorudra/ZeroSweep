import { describe, expect, it } from "vitest";
import {
  AmassParser, AssetfinderParser, DnsxParser, FindomainParser, SubfinderParser,
} from "./parsers-discovery";
import {
  GauParser, HttpxParser, KatanaParser, WaybackurlsParser, WhatWebParser,
} from "./parsers-web";
import * as F from "./fixtures";

/**
 * Parser tests (Prompt 5 §36–§37, §53): recorded fixtures only — no tool is
 * executed, no network is touched. Malformed lines must surface as warnings,
 * never as crashes.
 */

describe("subdomain discovery parsers", () => {
  it("subfinder: JSONL hosts canonicalized, malformed lines are warnings", () => {
    const out = new SubfinderParser().parse(F.SUBFINDER_JSONL);
    expect(out.assets.map((a) => a.host)).toEqual(["api.example.com", "www.example.com", "dev.example.com"]);
    expect(out.records).toBe(3);
    expect(out.warnings.length).toBeGreaterThanOrEqual(2); // non-JSON line + bad host
    expect(out.assets.every((a) => a.sources?.includes("subfinder"))).toBe(true);
  });

  it("amass: names + addresses + DNS record sets", () => {
    const out = new AmassParser().parse(F.AMASS_JSONL);
    const api = out.assets.find((a) => a.host === "api.example.com")!;
    expect(api.ip).toBe("93.184.216.34");
    expect(api.dnsRecords).toEqual([{ type: "A", values: ["93.184.216.34"] }]);
    expect(out.records).toBe(2);
    expect(out.warnings.length).toBe(1); // the broken JSON line
  });

  it("assetfinder + findomain: plain host lists, junk lines tolerated", () => {
    const af = new AssetfinderParser().parse(F.ASSETFINDER_TEXT);
    expect(af.assets.map((a) => a.host)).toEqual(["api.example.com", "staging.example.com"]);
    const fd = new FindomainParser().parse(F.FINDOMAIN_TEXT);
    expect(fd.assets.map((a) => a.host)).toEqual(["api.example.com", "blog.example.com"]);
    expect(fd.warnings.length).toBe(1);
  });
});

describe("dnsx parser (§9, §29)", () => {
  it("normalizes A/AAAA/CNAME and never assets the wildcard probe", () => {
    const out = new DnsxParser().parse(F.DNSX_JSONL);
    const hosts = out.assets.map((a) => a.host);
    expect(hosts).toContain("api.example.com");
    expect(hosts).not.toContain("nxprobe-deadbeef.example.com");
    const www = out.assets.find((a) => a.host === "www.example.com")!;
    expect(www.dnsRecords?.find((r) => r.type === "AAAA")?.values).toHaveLength(1);
    const api = out.assets.find((a) => a.host === "api.example.com")!;
    expect(api.dnsRecords?.find((r) => r.type === "CNAME")?.values).toEqual(["lb.example.net"]);
  });
  it("flags wildcard DNS and hosts that resolve only to the wildcard answer", () => {
    const out = new DnsxParser().parse(F.DNSX_JSONL);
    expect(out.metrics.wildcardDetected).toBe(1);
    expect(out.wildcardIpSet).toEqual(["203.0.113.99"]);
    const fake = out.assets.find((a) => a.host === "fake.example.com")!;
    expect(fake.wildcardSuspect).toBe(true);
    const api = out.assets.find((a) => a.host === "api.example.com")!;
    expect(api.wildcardSuspect).toBeUndefined();
  });
});

describe("httpx parser (§10)", () => {
  it("builds services + technologies; statuses stay metadata, never findings", () => {
    const out = new HttpxParser().parse(F.HTTPX_JSONL);
    expect(out.services).toHaveLength(3);
    const api = out.services.find((s) => s.host === "api.example.com")!;
    expect(api).toMatchObject({ port: 443, scheme: "https", statusCode: 200, title: "API Root", server: "nginx" });
    const techNames = out.technologies.map((t) => t.name);
    expect(techNames).toContain("nginx");
    expect(techNames).toContain("PHP");
    expect(out.warnings.length).toBe(1); // malformed line tolerated
  });
  it("records the third-party redirect target on the service (§30)", () => {
    const out = new HttpxParser().parse(F.HTTPX_JSONL);
    const www = out.services.find((s) => s.host === "www.example.com")!;
    expect(www.redirectLocation).toBe("https://login.thirdparty.example.net/");
  });
});

describe("whatweb parser (§11)", () => {
  it("parses the JSON plugin format with versions + certainty confidence", () => {
    const out = new WhatWebParser().parse(F.WHATWEB_JSON);
    const wp = out.technologies.find((t) => t.name === "WordPress")!;
    expect(wp).toMatchObject({ version: "6.4.2", category: "CMS", confidence: 1 });
    const nginx = out.technologies.find((t) => t.name === "nginx")!;
    expect(nginx.category).toBe("Web Server");
    expect(out.endpoints[0]).toMatchObject({ url: "https://www.example.com/", statusCode: 200 });
  });
  it("falls back to the brief stdout format", () => {
    const out = new WhatWebParser().parse(F.WHATWEB_BRIEF);
    expect(out.technologies.map((t) => t.name)).toEqual(["nginx", "PHP", "WordPress"]);
    expect(out.endpoints[0]?.statusCode).toBe(200);
  });
  it("empty output parses to an empty result, garbage warns", () => {
    expect(new WhatWebParser().parse("").records).toBe(0);
    expect(new WhatWebParser().parse("total garbage {{{").warnings.length).toBeGreaterThan(0);
  });
});

describe("historical URL parsers (§12–§13)", () => {
  it("gau: canonical URLs + parameter names; junk line is a warning", () => {
    const out = new GauParser().parse(F.GAU_TEXT);
    expect(out.endpoints).toHaveLength(3);
    expect(out.endpoints[0]?.parameterNames).toEqual(["id", "lang"]);
    expect(out.warnings).toHaveLength(1);
    expect(out.endpoints.every((e) => e.source === "gau")).toBe(true);
  });
  it("waybackurls: same normalization, own source label", () => {
    const out = new WaybackurlsParser().parse(F.WAYBACK_TEXT);
    expect(out.endpoints).toHaveLength(2);
    expect(out.endpoints.every((e) => e.source === "waybackurls")).toBe(true);
  });
});

describe("katana parser (§14)", () => {
  it("extracts endpoints with method/status/params; incomplete records warn", () => {
    const out = new KatanaParser().parse(F.KATANA_JSONL);
    expect(out.endpoints).toHaveLength(3);
    const search = out.endpoints.find((e) => e.url.includes("/search"))!;
    expect(search.method).toBe("POST");
    expect(search.parameterNames).toEqual(["page", "q"]);
    expect(out.warnings).toHaveLength(1);
  });
});
