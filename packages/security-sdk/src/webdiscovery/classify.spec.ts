import { describe, expect, it } from "vitest";
import {
  canonicalLookupForm, classifyEndpointType, detectCrawlerTrap, isApiRoute, isJavaScriptResource,
  isStaticResource, parseRobotsTxt, parseSitemapXml, prioritizeParameterTargets, sensitiveRouteLabel, volatileUrlKey,
} from "./classify";
import { ROBOTS_TXT, SITEMAP_INDEX_XML, SITEMAP_XML } from "./fixtures";
import { clampDiscoveryBudget, ADMIN_DISCOVERY_CAPS } from "../recon/budget";

describe("route classification (§41–§44)", () => {
  it("API route detection covers the spec examples", () => {
    for (const u of ["https://example.com/api/", "https://example.com/api/v1/users", "https://example.com/graphql", "https://example.com/rest/items", "https://example.com/v2/things"]) {
      expect(isApiRoute(u)).toBe(true);
    }
    expect(isApiRoute("https://example.com/about")).toBe(false);
    expect(classifyEndpointType("https://example.com/api/users")).toBe("API");
  });

  it("admin-style routes are SENSITIVE_ROUTE — a label, never a finding (§42)", () => {
    expect(sensitiveRouteLabel("https://example.com/admin")).toBe("SENSITIVE_ROUTE");
    expect(sensitiveRouteLabel("https://example.com/dashboard/settings")).toBe("SENSITIVE_ROUTE");
    expect(sensitiveRouteLabel("https://example.com/about")).toBeUndefined();
    expect(classifyEndpointType("https://example.com/admin")).toBe("PAGE");
  });

  it("static resources and JavaScript are classified for budget protection (§43/§44)", () => {
    expect(isStaticResource("https://example.com/img/logo.png")).toBe(true);
    expect(isStaticResource("https://example.com/search")).toBe(false);
    expect(isJavaScriptResource("https://example.com/assets/app.js")).toBe(true);
    expect(classifyEndpointType("https://example.com/assets/app.js")).toBe("STATIC");
    expect(classifyEndpointType("https://example.com/robots.txt")).toBe("FILE");
    expect(classifyEndpointType("https://example.com/docs/")).toBe("DIRECTORY");
  });
});

describe("normalization + duplicate control (§21/§45)", () => {
  it("canonical lookup form lowercases and unifies trailing slashes — stored evidence untouched", () => {
    expect(canonicalLookupForm("https://example.com/Admin")).toBe(canonicalLookupForm("https://example.com/admin/"));
    expect(canonicalLookupForm("https://example.com/ADMIN")).toBe("https://example.com/admin/");
  });

  it("volatile values collapse: ?id=1,2,3 are one representative endpoint", () => {
    const keys = ["https://example.com/item?id=1", "https://example.com/item?id=2", "https://example.com/item?id=3"].map(volatileUrlKey);
    expect(new Set(keys).size).toBe(1);
    expect(volatileUrlKey("https://example.com/item?id=1&lang=en")).not.toBe(keys[0]); // different parameter NAMES differ
  });
});

describe("crawler traps + explosion protection (§46/§47)", () => {
  it("flags deep loops, session segments and absurd pagination", () => {
    expect(detectCrawlerTrap("https://example.com/cal/2026/01/01/2026/01/01/2026/01/01").trap).toBe(true);
    expect(detectCrawlerTrap("https://example.com/x/abcdef0123456789abcdef0123456789abcdef01").trap).toBe(true);
    expect(detectCrawlerTrap("https://example.com/list?page=99999999").trap).toBe(true);
    expect(detectCrawlerTrap("https://example.com/search?q=shoes&page=2").trap).toBe(false);
    expect(detectCrawlerTrap("https://example.com/a/b", { siblingsSeen: 10_000 }).trap).toBe(true);
  });
});

describe("robots + sitemap (§24/§25)", () => {
  it("robots directives parse; sitemap references are extracted, not trusted", () => {
    const robots = parseRobotsTxt(ROBOTS_TXT);
    expect(robots.disallow).toEqual(["/admin", "/internal/"]);
    expect(robots.allow).toEqual(["/admin/public"]);
    expect(robots.sitemaps).toEqual(["https://example.com/sitemap.xml"]);
  });

  it("sitemap locations parse; an index yields child sitemaps, expansion stays with the caller", () => {
    const sm = parseSitemapXml(SITEMAP_XML);
    expect(sm.locations).toEqual(["https://example.com/", "https://example.com/about", "https://example.com/api/users"]);
    const index = parseSitemapXml(SITEMAP_INDEX_XML);
    expect(index.locations).toEqual([]);
    expect(index.childSitemaps).toHaveLength(2);
    const capped = parseSitemapXml(SITEMAP_XML, 2);
    expect(capped.locations).toHaveLength(2);
  });
});

describe("parameter target prioritization (§28)", () => {
  it("API + GET + live first; static and out-of-scope are excluded", () => {
    const input = [
      { url: "https://example.com/assets/app.js", method: "GET", statusCode: 200 },
      { url: "https://thirdparty.example.net/x", method: "GET", scopeStatus: "OUT_OF_SCOPE" as const },
      { url: "https://example.com/about", method: "GET" },
      { url: "https://example.com/api/users", method: "GET", statusCode: 200 },
      { url: "https://example.com/search", method: "POST", statusCode: 200 },
    ];
    const picked = prioritizeParameterTargets(input, 2);
    expect(picked.map((p) => p.url)).toEqual(["https://example.com/api/users", "https://example.com/about"]);
  });
});

describe("discovery budget — Prompt 6 fields (§14)", () => {
  it("new ceilings default conservatively and clamp to admin caps", () => {
    const d = clampDiscoveryBudget();
    expect(d.maxContentRequests).toBe(5_000);
    expect(d.maxRecursionDepth).toBe(3);
    const clamped = clampDiscoveryBudget({ maxContentRequests: 10_000_000, maxRecursionDepth: 99, maxWordlistEntries: 5 });
    expect(clamped.maxContentRequests).toBe(ADMIN_DISCOVERY_CAPS.maxContentRequests);
    expect(clamped.maxRecursionDepth).toBe(ADMIN_DISCOVERY_CAPS.maxRecursionDepth);
    expect(clamped.maxWordlistEntries).toBe(5); // lower requests honoured
  });
});
