import { describe, expect, it } from "vitest";
import {
  classifyDestination, evaluateDestination, expandCidrTargets, ipInCidr, iterateCidrHosts,
  parseCidr, parseIp, protectedDestinationReason, CidrPolicyService,
} from "./cidr";
import { buildNetworkScope, networkScopeContainsIp, revalidateHostname } from "./network-scope";
import { clampMasscanLimits, clampNetworkBudget, MASSCAN_HARD_LIMITS } from "./budget";
import { portProfileById, validateCustomPorts } from "./port-profiles";
import { sanitizeBanner } from "./sanitize";

describe("CIDR canonicalization + math (§3–§5)", () => {
  it("canonicalizes and computes network facts for a /24", () => {
    const info = parseCidr("192.0.2.77/24")!;
    expect(info.canonical).toBe("192.0.2.0/24");
    expect(info.networkAddress).toBe("192.0.2.0");
    expect(info.broadcastAddress).toBe("192.0.2.255");
    expect(info.addressCount).toBe(256);
    expect(info.hostCount).toBe(254);
    expect(info.firstHost).toBe("192.0.2.1");
    expect(info.lastHost).toBe("192.0.2.254");
  });

  it("a /32 is exactly one host; a bare IP is not a CIDR", () => {
    expect(parseCidr("192.0.2.10/32")!.hostCount).toBe(1);
    expect(parseCidr("192.0.2.10")).toBeNull();
    expect(parseCidr("999.1.1.1/24")).toBeNull();
    expect(parseCidr("192.0.2.0/33")).toBeNull();
  });

  it("membership works for v4 and v6", () => {
    expect(ipInCidr("192.0.2.55", "192.0.2.0/24")).toBe(true);
    expect(ipInCidr("192.0.3.1", "192.0.2.0/24")).toBe(false);
    expect(ipInCidr("2001:db8::1", "2001:db8::/32")).toBe(true);
    expect(ipInCidr("2001:db9::1", "2001:db8::/32")).toBe(false);
    expect(parseIp("::1")!.family).toBe(6);
  });

  it("bounded expansion: small ranges materialize, large ranges stream as chunks (§5)", () => {
    const small = expandCidrTargets("192.0.2.0/24")!;
    expect(small.kind).toBe("LIST");
    if (small.kind === "LIST") expect(small.hosts).toHaveLength(254);
    const large = expandCidrTargets("198.51.100.0/16")!;
    expect(large.kind).toBe("RANGES");
    if (large.kind === "RANGES") {
      expect(large.totalHosts).toBe(65534); // never materialized into a host list
    }
    expect(large.chunks.length).toBeGreaterThan(100);
    expect(large.chunks[0]).toMatchObject({ rangeStart: "198.51.0.1" });
    expect([...iterateCidrHosts("192.0.2.0/30")]).toEqual(["192.0.2.1", "192.0.2.2"]);
  });
});

describe("protected destinations (§6)", () => {
  it("loopback, link-local, metadata and private ranges classify correctly", () => {
    expect(classifyDestination("203.0.113.9")).toBe("PUBLIC");
    expect(classifyDestination("10.0.0.5")).toBe("PRIVATE_INTERNAL");
    expect(classifyDestination("127.0.0.1")).toBe("PROTECTED");
    expect(classifyDestination("169.254.169.254")).toBe("PROTECTED");
    expect(classifyDestination("100.64.1.1")).toBe("PRIVATE_INTERNAL"); // CGNAT shared space
    expect(protectedDestinationReason("169.254.169.254")).toMatch(/metadata/);
  });

  it("PROTECTED is denied even with an approved internal engagement", () => {
    expect(evaluateDestination("127.0.0.1", { internalEngagementApproved: true }).allowed).toBe(false);
    expect(evaluateDestination("169.254.169.254", { internalEngagementApproved: true }).allowed).toBe(false);
  });

  it("private ranges need the approved internal engagement (§6/§64)", () => {
    expect(evaluateDestination("10.1.2.3", {}).allowed).toBe(false);
    expect(evaluateDestination("10.1.2.3", { internalEngagementApproved: true }).allowed).toBe(true);
    expect(evaluateDestination("203.0.113.9", {}).allowed).toBe(true);
  });

  it("IPv4-mapped / compatible / NAT64 spellings classify as their embedded IPv4 (NV hardening)", () => {
    expect(classifyDestination("::ffff:127.0.0.1")).toBe("PROTECTED");
    expect(classifyDestination("::ffff:7f00:1")).toBe("PROTECTED"); // hex tail form
    expect(classifyDestination("::ffff:169.254.169.254")).toBe("PROTECTED");
    expect(classifyDestination("::ffff:10.0.0.1")).toBe("PRIVATE_INTERNAL");
    expect(classifyDestination("::127.0.0.1")).toBe("PROTECTED"); // compatible
    expect(classifyDestination("::10.0.0.1")).toBe("PRIVATE_INTERNAL");
    expect(classifyDestination("64:ff9b::127.0.0.1")).toBe("PROTECTED"); // NAT64
    expect(classifyDestination("64:ff9b:1::a00:1")).toBe("PRIVATE_INTERNAL"); // NAT64 local, hex tail
    expect(classifyDestination("::ffff:203.0.113.9")).toBe("PUBLIC"); // mapped public stays public
    expect(evaluateDestination("::ffff:127.0.0.1", { internalEngagementApproved: true }).allowed).toBe(false);
    expect(ipInCidr("::ffff:127.0.0.1", "127.0.0.0/8")).toBe(true);
    expect(ipInCidr("64:ff9b::10.0.0.1", "10.0.0.0/8")).toBe(true);
  });

  it("non-canonical IPv4 encodings are rejected and fail closed (NV hardening)", () => {
    expect(parseIp("0177.0.0.1")).toBeNull(); // leading-zero (octal in other parsers)
    expect(parseIp("010.0.0.1")).toBeNull();
    expect(parseIp("0.0.0.0")).not.toBeNull(); // a bare "0" part is canonical
    expect(classifyDestination("0177.0.0.1")).toBe("PROTECTED");
    expect(evaluateDestination("0177.0.0.1", {}).allowed).toBe(false);
  });

  it("platform-infrastructure CIDRs are protected by configuration", () => {
    const opts = { internalEngagementApproved: true, extraProtectedCidrs: ["198.51.100.0/24"] };
    expect(evaluateDestination("198.51.100.7", opts).allowed).toBe(false);
  });
});

describe("CidrPolicyService thresholds (§4)", () => {
  const svc = new CidrPolicyService();
  it("tiers and approvals follow the thresholds", () => {
    expect(svc.evaluate("192.0.2.10/32")).toMatchObject({ tier: "SINGLE_HOST", approval: "NORMAL" });
    expect(svc.evaluate("192.0.2.0/24")).toMatchObject({ tier: "SMALL", approval: "NORMAL" });
    expect(svc.evaluate("192.0.2.0/20")).toMatchObject({ tier: "LARGE", approval: "ELEVATED" });
    expect(svc.evaluate("198.51.100.0/16")).toMatchObject({ tier: "VERY_LARGE", approval: "ADMINISTRATOR" });
    expect(svc.evaluate("203.0.0.0/8")).toMatchObject({ approval: "DENY" });
    expect(svc.evaluate("203.0.0.0/8")!.allowed).toBe(false);
  });
});

describe("NetworkScope + DNS revalidation (§3/§7)", () => {
  const scope = buildNetworkScope({
    includeHosts: [], includeCidrs: ["192.0.2.0/24"], excludeHosts: ["192.0.2.99"],
    allowedPorts: [], allowedPaths: [], excludedPaths: [],
  });
  it("exclusions always win", () => {
    expect(networkScopeContainsIp(scope, "192.0.2.10").allowed).toBe(true);
    expect(networkScopeContainsIp(scope, "192.0.2.99").allowed).toBe(false);
    expect(networkScopeContainsIp(scope, "198.51.100.9").allowed).toBe(false);
  });

  it("a hostname resolving out of scope or into a protected range fails revalidation entirely", async () => {
    const ok = await revalidateHostname(scope, "server.example.com", async () => ["192.0.2.10"]);
    expect(ok.allowed).toBe(true);
    const rebinding = await revalidateHostname(scope, "server.example.com", async () => ["192.0.2.10", "10.0.0.5"]);
    expect(rebinding.allowed).toBe(false);
    expect(rebinding.blockedAddresses.map((b) => b.ip)).toContain("10.0.0.5");
    const empty = await revalidateHostname(scope, "server.example.com", async () => []);
    expect(empty.allowed).toBe(false);
  });
});

describe("budgets clamp, never raise (§20/§56)", () => {
  it("user values are clamped to administrator caps", () => {
    const b = clampNetworkBudget({ maxHosts: 10 ** 9, maxPortsPerHost: 5 });
    expect(b.maxHosts).toBe(65536);
    expect(b.maxPortsPerHost).toBe(5);
    expect(b.maxTotalPorts).toBeLessThanOrEqual(b.maxHosts * b.maxPortsPerHost);
  });
  it("Masscan limits have hard platform ceilings", () => {
    const m = clampMasscanLimits({ maxRate: 10 ** 9, maxTargets: 10 ** 9 });
    expect(m.maxRate).toBe(MASSCAN_HARD_LIMITS.maxRate);
    expect(m.maxTargets).toBe(MASSCAN_HARD_LIMITS.maxTargets);
  });
});

describe("port profiles + custom sets (§27)", () => {
  it("FULL_TCP is never the default profile", () => {
    expect(portProfileById("FULL_TCP")!.broad).toBe(true);
    expect(portProfileById("COMMON_SERVICES")!.broad).toBe(false);
  });
  it("custom ports are validated structured input", () => {
    expect(validateCustomPorts([443, 80, 80])).toEqual([80, 443]);
    expect(validateCustomPorts([0])).toBeNull();
    expect(validateCustomPorts([70000])).toBeNull();
    expect(validateCustomPorts(["80"])).toBeNull();
    expect(validateCustomPorts("80,443")).toBeNull();
  });
});

describe("banner sanitization (§36)", () => {
  it("strips escapes, neutralizes markup and caps size", () => {
    const out = sanitizeBanner("Apache <script>alert(1)</script>\u001b[31mred")!;
    expect(out).not.toContain("<script>");
    expect(out).not.toContain("\u001b");
    expect(out).toContain("&lt;script&gt;");
    expect(sanitizeBanner("x".repeat(5000))!.length).toBeLessThanOrEqual(513);
    expect(sanitizeBanner("")).toBeUndefined();
  });
});
