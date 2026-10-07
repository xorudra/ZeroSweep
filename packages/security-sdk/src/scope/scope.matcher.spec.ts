import { describe, expect, it } from "vitest";
import { blockedTargetReason, cidrContains, ScopeMatcher } from "./scope.matcher";

const rules = {
  includeHosts: ["example.com", "*.example.com"],
  excludeHosts: ["admin.example.com"],
  includeCidrs: [] as string[],
  allowedPorts: [80, 443],
  allowedPaths: ["/"],
  excludedPaths: ["/logout"],
};

describe("ScopeMatcher", () => {
  const m = new ScopeMatcher(rules);
  it("allows listed hosts and subdomains", () => {
    expect(m.isHostAllowed("example.com")).toBe(true);
    expect(m.isHostAllowed("app.example.com")).toBe(true);
    expect(m.isHostAllowed("deep.app.example.com")).toBe(true);
  });
  it("denies unlisted and excluded hosts", () => {
    expect(m.isHostAllowed("other.com")).toBe(false);
    expect(m.isHostAllowed("admin.example.com")).toBe(false);
    expect(m.isHostAllowed("notexample.com")).toBe(false);
  });
  it("checks port and path", () => {
    expect(m.isPortAllowed(443)).toBe(true);
    expect(m.isPortAllowed(22)).toBe(false);
    expect(m.isPathAllowed("/api/users")).toBe(true);
    expect(m.isPathAllowed("/logout")).toBe(false);
  });
  it("validates full URLs", () => {
    expect(m.isUrlAllowed("https://app.example.com/api")).toBe(true);
    expect(m.isUrlAllowed("https://app.example.com:22/api")).toBe(false);
    expect(m.isUrlAllowed("javascript:alert(1)")).toBe(false);
  });
});

describe("cidrContains", () => {
  it("matches inside/outside addresses", () => {
    expect(cidrContains("10.0.0.0/24", "10.0.0.55")).toBe(true);
    expect(cidrContains("10.0.0.0/24", "10.0.1.55")).toBe(false);
    expect(cidrContains("0.0.0.0/0", "8.8.8.8")).toBe(true);
  });
});

describe("blockedTargetReason (SSRF / internal protection)", () => {
  it("blocks loopback, link-local and metadata", () => {
    expect(blockedTargetReason("127.0.0.1")).not.toBeNull();
    expect(blockedTargetReason("169.254.169.254")).not.toBeNull();
    expect(blockedTargetReason("localhost")).not.toBeNull();
    expect(blockedTargetReason("192.168.1.10")).not.toBeNull();
  });
  it("allows public hosts", () => {
    expect(blockedTargetReason("example.com")).toBeNull();
    expect(blockedTargetReason("8.8.8.8")).toBeNull();
  });
});
