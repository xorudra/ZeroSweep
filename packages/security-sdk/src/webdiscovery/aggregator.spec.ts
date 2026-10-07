import { describe, expect, it } from "vitest";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { ScopeMatcher } from "../scope/scope.matcher";
import { WebSurfaceAggregator } from "./aggregator";
import { Soft404Detector } from "./soft404";
import { SOFT404_BASELINE } from "./fixtures";
import { FfufParser, GobusterParser, WfuzzParser, ArjunParser } from "./parsers-webdiscovery";
import * as F from "./fixtures";
import { buildEndpointGraph } from "./graph";

function result(partial: Partial<NormalizedSecurityResult>): NormalizedSecurityResult {
  return { assets: [], services: [], endpoints: [], technologies: [], findings: [], artifacts: [], metrics: {}, mock: false, ...partial };
}
const scope = new ScopeMatcher({ includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] });

describe("WebSurfaceAggregator (§39–§43)", () => {
  it("provenance: one canonical endpoint, many sources (§26)", () => {
    const agg = new WebSurfaceAggregator(scope);
    const out = agg.aggregate([
      { tool: "katana", result: result({ endpoints: [{ url: "https://example.com/admin", method: "GET", source: "katana", parameterNames: [] }] }) },
      { tool: "ffuf", result: new FfufParser().parse(F.FFUF_JSON) as never },
    ]);
    const admin = out.endpoints.find((e) => e.url === "https://example.com/admin")!;
    expect(admin.sources).toEqual(["ffuf", "katana"]);
    expect(admin.classification).toBe("SENSITIVE_ROUTE"); // label only (§42)
    expect(out.findings).toEqual([]);
    expect(out.metrics.duplicatesRemoved).toBeGreaterThanOrEqual(1);
  });

  it("scope verdicts on every route; out-of-scope recorded, never promoted (§40)", () => {
    const agg = new WebSurfaceAggregator(scope);
    const out = agg.aggregate([
      { tool: "gau", result: result({ endpoints: [
        { url: "https://example.com/ok", method: "GET", source: "gau", parameterNames: [] },
        { url: "https://thirdparty.example.net/leak", method: "GET", source: "gau", parameterNames: [] },
      ] }) },
    ]);
    expect(out.endpoints.find((e) => e.url.includes("thirdparty"))!.scopeStatus).toBe("OUT_OF_SCOPE");
    expect(out.metrics.outOfScopeRejected).toBe(1);
    expect(out.metrics.endpointsInScope).toBe(1);
  });

  it("soft-404 twins are filtered once calibrated (§17)", () => {
    const agg = new WebSurfaceAggregator(scope, { soft404: new Soft404Detector([SOFT404_BASELINE]) });
    const out = agg.aggregate([{ tool: "ffuf", result: new FfufParser().parse(F.FFUF_JSON) as never }]);
    expect(out.endpoints.some((e) => e.url.includes("zzz-nonexistent"))).toBe(false);
    expect(out.metrics.soft404Filtered).toBe(2);
    // Uncalibrated, the same twins survive — detection never guesses.
    const plain = new WebSurfaceAggregator(scope).aggregate([{ tool: "ffuf", result: new FfufParser().parse(F.FFUF_JSON) as never }]);
    expect(plain.endpoints.some((e) => e.url.includes("zzz-nonexistent-a"))).toBe(true);
  });

  it("in-scope redirects recorded; out-of-scope destinations recorded only (§20/§23)", () => {
    const agg = new WebSurfaceAggregator(scope);
    const out = agg.aggregate([{ tool: "gobuster", result: new GobusterParser("https://example.com/").parse(F.GOBUSTER_TEXT) as never }]);
    const images = out.endpoints.find((e) => e.url === "https://example.com/images")!;
    expect(images.redirectLocation).toBe("https://example.com/images/");
    expect(images.scopeStatus).toBe("IN_SCOPE");
  });

  it("parameter provenance dedupes across tools (§30) and attaches only in scope (§28)", () => {
    const agg = new WebSurfaceAggregator(scope);
    const out = agg.aggregate([
      { tool: "arjun", result: new ArjunParser().parse(F.ARJUN_JSON) as never },
      { tool: "wfuzz", result: new WfuzzParser().parse(F.WFUZZ_JSON) as never },
    ]);
    const id = out.parameters!.find((p) => p.endpointUrl === "https://example.com/search" && p.name === "id")!;
    expect(id.sources).toEqual(["arjun", "wfuzz"]);
    expect(out.parameters!.filter((p) => p.endpointUrl === "https://example.com/search").map((p) => p.name).sort()).toEqual(["id", "page", "q", "sort"]);
    expect(out.endpoints.find((e) => e.url === "https://example.com/api/users")!.endpointType).toBe("API");
  });

  it("endpoint graph links asset → service → endpoint → parameter (§31)", () => {
    const graph = buildEndpointGraph({
      assets: [{ host: "example.com", type: "DOMAIN", sources: ["subfinder"] }],
      services: [{ host: "example.com", port: 443, protocol: "tcp", scheme: "https" }],
      endpoints: [{ url: "https://example.com/search", method: "GET", source: "katana", parameterNames: ["q"] }],
      parameters: [{ endpointUrl: "https://example.com/search", name: "q", location: "QUERY", sources: ["arjun"] }],
    });
    expect(graph.nodes.map((n) => n.kind)).toEqual(["ASSET", "SERVICE", "ENDPOINT", "PARAMETER"]);
    expect(graph.edges.map((e) => e.relation)).toEqual(["HOSTS", "EXPOSES", "HAS_PARAMETER"]);
  });
});
