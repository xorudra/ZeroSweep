import { describe, expect, it } from "vitest";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import { ScopeMatcher } from "../scope/scope.matcher";
import { ReconResultAggregator } from "./aggregator";
import { BudgetTracker, clampDiscoveryBudget } from "./budget";
import { TenantSafeReconCache } from "./cache";

const SCOPE = { includeHosts: ["example.com", "*.example.com"], excludeHosts: [], includeCidrs: [], allowedPorts: [80, 443], allowedPaths: [], excludedPaths: [] };

function result(partial: Partial<NormalizedSecurityResult>): NormalizedSecurityResult {
  return { assets: [], services: [], endpoints: [], technologies: [], findings: [], artifacts: [], metrics: {}, mock: false, ...partial };
}

describe("ReconResultAggregator (§17–§18, §23)", () => {
  it("merges the same host from two tools into ONE asset with both sources", () => {
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE));
    const merged = agg.aggregate([
      { tool: "subfinder", result: result({ assets: [{ host: "API.example.com", type: "SUBDOMAIN", sources: ["subfinder"] }] }) },
      { tool: "amass", result: result({ assets: [{ host: "api.example.com", type: "SUBDOMAIN", sources: ["amass"], ip: "93.184.216.34" }] }) },
    ]);
    expect(merged.assets).toHaveLength(1);
    expect(merged.assets[0]).toMatchObject({ host: "api.example.com", ip: "93.184.216.34", scopeStatus: "IN_SCOPE" });
    expect(merged.assets[0]?.sources).toEqual(["amass", "subfinder"]);
    expect(merged.metrics.duplicatesRemoved).toBe(1);
  });

  it("records out-of-scope discoveries as OUT_OF_SCOPE, never promoted", () => {
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE));
    const merged = agg.aggregate([
      { tool: "subfinder", result: result({ assets: [{ host: "analytics.vendor.example.net", type: "SUBDOMAIN" }, { host: "ok.example.com", type: "SUBDOMAIN" }] }) },
    ]);
    expect(merged.assets.find((a) => a.host === "analytics.vendor.example.net")?.scopeStatus).toBe("OUT_OF_SCOPE");
    expect(merged.metrics.assetsOutOfScope).toBe(1);
    expect(merged.metrics.assetsInScope).toBe(1);
  });

  it("dedupes endpoints, merges parameter names, redacts sensitive values", () => {
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE));
    const merged = agg.aggregate([
      { tool: "gau", result: result({ endpoints: [{ url: "https://example.com/p?id=1&token=secretvalue", parameterNames: ["id", "token"], source: "gau" }] }) },
      { tool: "waybackurls", result: result({ endpoints: [{ url: "https://example.com/p?id=2&lang=en", parameterNames: ["id", "lang"], source: "waybackurls" }] }) },
    ]);
    expect(merged.endpoints).toHaveLength(1);
    expect(merged.endpoints[0]?.parameterNames).toEqual(["id", "lang", "token"]);
    expect(merged.endpoints[0]?.url).not.toContain("secretvalue");
    expect(merged.endpoints[0]?.url).toContain("token=REDACTED");
  });

  it("an out-of-scope redirect becomes a reference endpoint, not an asset (§30)", () => {
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE));
    const merged = agg.aggregate([
      { tool: "httpx", result: result({
        assets: [{ host: "www.example.com", type: "HOST" }],
        services: [{ host: "www.example.com", port: 443, protocol: "tcp", scheme: "https", redirectLocation: "https://login.thirdparty.example.net/" }],
      }) },
    ]);
    expect(merged.assets.map((a) => a.host)).toEqual(["www.example.com"]);
    const ref = merged.endpoints.find((e) => e.url.includes("thirdparty"))!;
    expect(ref.scopeStatus).toBe("OUT_OF_SCOPE");
  });

  it("strips any findings a recon result tries to carry (§47)", () => {
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE));
    const merged = agg.aggregate([
      { tool: "httpx", result: result({ findings: [{ title: "fake", description: "x", severity: "HIGH", confidence: 1, references: [], sourceTool: "httpx", sourceFingerprint: "f" }] }) },
    ]);
    expect(merged.findings).toEqual([]);
    expect(merged.metrics.findingsDropped).toBe(1);
  });

  it("budget caps truncate excess subdomains and say so in metrics (§28)", () => {
    const budget = new BudgetTracker(clampDiscoveryBudget({ maxSubdomains: 1 }));
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE), budget);
    const merged = agg.aggregate([
      { tool: "subfinder", result: result({ assets: [{ host: "a.example.com", type: "SUBDOMAIN" }, { host: "b.example.com", type: "SUBDOMAIN" }] }) },
    ]);
    expect(merged.assets).toHaveLength(1);
    expect(merged.metrics.budgetTruncatedAssets).toBe(1);
  });

  it("wildcard-suspect hosts are carried through and flagged in metrics (§29)", () => {
    const agg = new ReconResultAggregator(new ScopeMatcher(SCOPE));
    const merged = agg.aggregate([
      { tool: "dnsx", result: result({ assets: [{ host: "fake.example.com", type: "HOST", wildcardSuspect: true }], metrics: { wildcardDetected: 1 } }) },
    ]);
    expect(merged.assets[0]?.wildcardSuspect).toBe(true);
    expect(merged.metrics.wildcardDetected).toBe(1);
  });
});

describe("TenantSafeReconCache (§49)", () => {
  it("keys are tenant-scoped and entries expire", () => {
    let now = 0;
    const cache = new TenantSafeReconCache(1_000, () => now);
    const keyA = TenantSafeReconCache.key("org-a", "ws-1", "gau", "example.com", "cfg1");
    const keyB = TenantSafeReconCache.key("org-b", "ws-1", "gau", "example.com", "cfg1");
    expect(keyA).not.toBe(keyB);
    cache.set(keyA, result({}));
    expect(cache.get(keyA)).toBeDefined();
    expect(cache.get(keyB)).toBeUndefined();
    now = 2_000;
    expect(cache.get(keyA)).toBeUndefined();
  });
});
