import { describe, expect, it } from "vitest";
import { ToolRegistry } from "../registry/registry";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import { FixtureToolRunner } from "./runner";
import { createReconAdapters, reconHealthBySlug, registerReconAdapters, RECON_SLUGS } from "./registry";
import { DnsxAdapter, SubfinderAdapter } from "./adapters-discovery";
import { HttpxAdapter, KatanaAdapter, WaybackurlsAdapter } from "./adapters-web";
import * as F from "./fixtures";

const DOMAIN = { type: "DOMAIN" as const, value: "example.com", host: "example.com" };
const WEBAPP = { type: "WEB_APPLICATION" as const, value: "https://example.com", host: "example.com" };

describe("recon adapter registration (§2, Prompt 3 SDK contract)", () => {
  it("all 10 adapters register cleanly and resolve by capability/target", () => {
    const registry = new ToolRegistry();
    const adapters = registerReconAdapters(registry, new FixtureToolRunner());
    expect(adapters.map((a) => a.metadata.slug).sort()).toEqual([...RECON_SLUGS].sort());
    expect(registry.byCapability("SUBDOMAIN_DISCOVERY").map((a) => a.metadata.slug).sort())
      .toEqual(["amass", "assetfinder", "findomain", "subfinder"]);
    expect(registry.byCapability("DNS_RESOLUTION").map((a) => a.metadata.slug)).toEqual(["dnsx"]);
    expect(registry.byCapability("HISTORICAL_URL_DISCOVERY").map((a) => a.metadata.slug).sort()).toEqual(["gau", "waybackurls"]);
    expect(registry.query({ targetType: "WEB_APPLICATION" }).map((a) => a.metadata.slug)).toContain("katana");
    expect(registry.query({ targetType: "DOMAIN" }).map((a) => a.metadata.slug)).not.toContain("katana");
    // No recon adapter requires approval or is RESTRICTED; none declares a
    // raw-command input (registry validation would have thrown already).
    for (const a of adapters) {
      expect(a.metadata.requiresApproval).toBe(false);
      expect(a.metadata.riskLevel).not.toBe("RESTRICTED");
      expect(a.metadata.riskLevel).not.toBe("INTRUSIVE");
    }
  });
});

describe("execution plans: argument arrays only (§11, §14)", () => {
  it("subfinder plan is the documented passive invocation", async () => {
    const plan = await new SubfinderAdapter(new FixtureToolRunner()).buildExecutionPlan(DOMAIN, {});
    expect(plan.executable).toBe("subfinder");
    expect(plan.arguments).toEqual(["-d", "example.com", "-json", "-silent"]);
    expect(plan.networkPolicy).toBe("INTERNET_READ_ONLY");
    expect(plan.containerImage).toBe("projectdiscovery/subfinder");
  });

  it("dnsx plan feeds authorized hosts + wildcard probe via stdin", async () => {
    const plan = await new DnsxAdapter(new FixtureToolRunner()).buildExecutionPlan(DOMAIN, { hosts: ["api.example.com", "www.example.com"] });
    expect(plan.arguments).toContain("-json");
    const stdinLines = (plan.stdin ?? "").split("\n");
    expect(stdinLines.slice(0, 2)).toEqual(["api.example.com", "www.example.com"]);
    expect(stdinLines[2]).toMatch(/^nxprobe-[0-9a-f]{8}\.example\.com$/);
  });

  it("httpx plan does not follow redirects and rate-limits conservatively", async () => {
    const plan = await new HttpxAdapter(new FixtureToolRunner()).buildExecutionPlan(DOMAIN, { hosts: ["api.example.com"] });
    expect(plan.arguments).not.toContain("-follow-redirects");
    expect(plan.arguments).not.toContain("-follow-host-redirects");
    expect(plan.arguments).toContain("-rate-limit");
    expect(plan.stdin).toBe("api.example.com");
  });

  it("katana plan locks scope to the root domain, caps depth, never fills forms", async () => {
    const adapter = new KatanaAdapter(new FixtureToolRunner());
    // Depth above the hard cap is refused by schema validation (§14)…
    await expect(adapter.buildExecutionPlan(WEBAPP, { depth: 99 })).rejects.toBeInstanceOf(AdapterConfigurationError);
    // …and the maximum legitimate depth is what the plan carries.
    const plan = await adapter.buildExecutionPlan(WEBAPP, { depth: 3 });
    const dIdx = plan.arguments.indexOf("-d");
    expect(plan.arguments[dIdx + 1]).toBe("3"); // hard cap (§14)
    expect(plan.arguments).toContain("-fs");
    expect(plan.arguments[plan.arguments.indexOf("-fs") + 1]).toBe("rdn");
    for (const forbidden of ["-aff", "-automatic-form-fill", "-form", "-fuzz"]) {
      expect(plan.arguments).not.toContain(forbidden);
    }
    expect(plan.arguments.join(" ")).not.toMatch(/[;|&`$]/); // no shell syntax anywhere
  });

  it("waybackurls takes the domain via stdin and no arguments", async () => {
    const plan = await new WaybackurlsAdapter(new FixtureToolRunner()).buildExecutionPlan(DOMAIN, {});
    expect(plan.arguments).toEqual([]);
    expect(plan.stdin).toBe("example.com\n");
  });

  it("configuration validation still rejects raw commands and unknown keys", async () => {
    const adapter = new SubfinderAdapter(new FixtureToolRunner());
    await expect(adapter.validateConfiguration({ command: "rm -rf /" } as never)).rejects.toBeInstanceOf(AdapterConfigurationError);
    await expect(adapter.validateConfiguration({ bogus: 1 })).rejects.toBeInstanceOf(AdapterConfigurationError);
  });
});

describe("health + fixture execution (§2, §4, §38)", () => {
  it("missing binaries report UNAVAILABLE honestly — health never crashes", async () => {
    const adapter = new SubfinderAdapter(new FixtureToolRunner({}));
    expect(adapter.isExecutablePresent()).toBe(false);
    expect(await adapter.checkAvailability()).toBe(false);
    const health = await adapter.healthCheck();
    expect(health.status).toBe("UNAVAILABLE");
    await expect(adapter.execute(await adapter.buildExecutionPlan(DOMAIN, {}))).rejects.toThrow(/not available/);
  });

  it("plan-time health map reflects binary presence (§39)", () => {
    const runner = new FixtureToolRunner({ subfinder: { stdout: "" } });
    const adapters = createReconAdapters(runner);
    const health = reconHealthBySlug(adapters);
    expect(health.subfinder).toBe("HEALTHY");
    expect(health.dnsx).toBe("UNAVAILABLE");
    expect(health.mock).toBeUndefined();
  });

  it("fixture run: subfinder executes, parses and normalizes to assets with zero findings", async () => {
    const runner = new FixtureToolRunner({ subfinder: { stdout: F.SUBFINDER_JSONL, version: "2.6.6" } });
    const adapter = new SubfinderAdapter(runner);
    const health = await adapter.healthCheck();
    expect(health.status).toBe("HEALTHY");
    expect(health.detail).toContain("2.6.6");
    const plan = await adapter.buildExecutionPlan(DOMAIN, {});
    const { rawOutput } = await adapter.execute(plan);
    const normalized = await adapter.normalize(await adapter.parse(rawOutput ?? ""));
    expect(normalized.assets.map((a) => a.host)).toEqual(["api.example.com", "www.example.com", "dev.example.com"]);
    expect(normalized.findings).toEqual([]);
    expect(normalized.mock).toBe(false);
    expect(normalized.metrics.parserWarnings).toBeGreaterThanOrEqual(2);
  });

  it("PARTIAL outcome: non-zero exit WITH output still parses (§38)", async () => {
    const runner = new FixtureToolRunner({ httpx: { stdout: F.HTTPX_JSONL, exitCode: 1 } });
    const adapter = new HttpxAdapter(runner);
    const plan = await adapter.buildExecutionPlan(DOMAIN, { hosts: ["api.example.com"] });
    const { rawOutput } = await adapter.execute(plan);
    const normalized = await adapter.normalize(await adapter.parse(rawOutput ?? ""));
    expect(normalized.services).toHaveLength(3);
    expect(normalized.metrics.outcomePartial).toBe(1);
  });

  it("FAILED outcome: non-zero exit with NO output throws a tool error (§38)", async () => {
    const runner = new FixtureToolRunner({ httpx: { stdout: "", exitCode: 2 } });
    const adapter = new HttpxAdapter(runner);
    const plan = await adapter.buildExecutionPlan(DOMAIN, { hosts: ["api.example.com"] });
    await expect(adapter.execute(plan)).rejects.toThrow(/tool execution failed/);
  });

  it("TIMED_OUT outcome throws the timeout error (§38)", async () => {
    const runner = new FixtureToolRunner({ httpx: { stdout: "", exitCode: null as never, timedOut: true } });
    const adapter = new HttpxAdapter(runner);
    const plan = await adapter.buildExecutionPlan(DOMAIN, { hosts: ["api.example.com"] });
    await expect(adapter.execute(plan)).rejects.toThrow(/timeout/i);
  });
});
