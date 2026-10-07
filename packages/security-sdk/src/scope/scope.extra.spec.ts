import { describe, expect, it } from "vitest";
import { blockedTargetReason, cidrContains, ScopeMatcher } from "./scope.matcher";
import { validateScopeRules } from "./scope.validation";

const rules = { includeHosts: ["example.com", "*.example.com"], excludeHosts: ["admin.example.com"], includeCidrs: ["203.0.113.0/24"], allowedPorts: [] as number[], allowedPaths: [] as string[], excludedPaths: [] as string[] };

describe("ScopeMatcher — extended", () => {
  const m = new ScopeMatcher(rules);
  it("matches IPs against CIDR includes", () => {
    expect(m.isIpAllowed("203.0.113.7")).toBe(true);
    expect(m.isIpAllowed("203.0.114.7")).toBe(false);
    expect(m.isHostAllowed("203.0.113.7")).toBe(true);
  });
  it("discovered assets never expand scope", () => {
    expect(m.isDiscoveredAssetInScope("new.example.com").allowed).toBe(true);
    expect(m.isDiscoveredAssetInScope("admin.example.com").allowed).toBe(false);
    expect(m.isDiscoveredAssetInScope("other.org").allowed).toBe(false);
  });
  it("rejects URLs with embedded credentials and internal targets", () => {
    expect(m.isUrlAllowed("https://user:pass@example.com/")).toBe(false);
    expect(m.isUrlAllowed("http://127.0.0.1/")).toBe(false);
    expect(m.isUrlAllowed("https://example.com/")).toBe(true);
  });
  it("cidrContains rejects malformed input", () => {
    expect(cidrContains("10.0.0.0/33", "10.0.0.1")).toBe(false);
    expect(cidrContains("bogus", "10.0.0.1")).toBe(false);
    expect(cidrContains("10.0.0.0/24", "999.0.0.1")).toBe(false);
  });
  it("blocks IPv6 loopback/ULA/link-local and CGNAT by default", () => {
    expect(blockedTargetReason("::1")).not.toBeNull();
    expect(blockedTargetReason("fd00::1")).not.toBeNull();
    expect(blockedTargetReason("fe80::1")).not.toBeNull();
    expect(blockedTargetReason("100.64.0.1")).not.toBeNull();
  });
});

describe("validateScopeRules", () => {
  it("accepts a clean scope and flags broken rules", () => {
    expect(validateScopeRules(rules)).toEqual([]);
    expect(validateScopeRules({ ...rules, includeCidrs: ["10.0.0.0/99"] }).length).toBe(1);
    expect(validateScopeRules({ ...rules, allowedPorts: [70000] }).length).toBe(1);
    expect(validateScopeRules({ ...rules, allowedPaths: ["relative"] }).length).toBe(1);
  });
});
