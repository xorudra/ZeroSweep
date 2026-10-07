import { describe, expect, it } from "vitest";
import { ToolRegistry } from "../registry/registry";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import { FixtureToolRunner } from "../recon/runner";
import { createWebDiscoveryAdapters, registerWebDiscoveryAdapters, WEB_DISCOVERY_SLUGS } from "./registry";
import { ArjunAdapter, FeroxbusterAdapter, FfufAdapter, GobusterAdapter, WfuzzAdapter } from "./adapters-webdiscovery";
import * as F from "./fixtures";

const WEBAPP = { type: "WEB_APPLICATION" as const, value: "https://example.com", host: "example.com" };

describe("web-discovery adapter registration (§2)", () => {
  it("all 5 adapters register and resolve by capability", () => {
    const registry = new ToolRegistry();
    const adapters = registerWebDiscoveryAdapters(registry, new FixtureToolRunner());
    expect(adapters.map((a) => a.metadata.slug).sort()).toEqual([...WEB_DISCOVERY_SLUGS].sort());
    expect(registry.byCapability("CONTENT_DISCOVERY").map((a) => a.metadata.slug).sort()).toEqual(["feroxbuster", "ffuf", "gobuster", "wfuzz"]);
    expect(registry.byCapability("PARAMETER_DISCOVERY").map((a) => a.metadata.slug).sort()).toEqual(["arjun", "wfuzz"]);
    expect(registry.byCapability("DIRECTORY_DISCOVERY").map((a) => a.metadata.slug).sort()).toEqual(["feroxbuster", "ffuf", "gobuster"]);
    for (const a of adapters) {
      expect(a.metadata.requiresApproval).toBe(false);
      expect(a.metadata.riskLevel).not.toBe("INTRUSIVE");
    }
  });
});

describe("execution plans: argument arrays, registered wordlists, hard caps (§3–§7, §11, §15)", () => {
  it("ffuf plan fuzzes with the registered SMALL list and conservative rate defaults", async () => {
    const plan = await new FfufAdapter(new FixtureToolRunner()).buildExecutionPlan(WEBAPP, {});
    expect(plan.executable).toBe("ffuf");
    expect(plan.arguments[plan.arguments.indexOf("-w") + 1]).toBe("/wordlists/builtin/common-directories-small.txt");
    expect(plan.arguments).toContain("https://example.com/FUZZ");
    expect(plan.arguments[plan.arguments.indexOf("-rate") + 1]).toBe("10"); // conservative default (§15)
    expect(plan.arguments).not.toContain("-r"); // redirects recorded, never followed (§20)
    expect(plan.arguments.join(" ")).not.toMatch(/[;|&`]/);
  });

  it("ffuf vhost mode is a separate, explicit plan (§3)", async () => {
    const plan = await new FfufAdapter(new FixtureToolRunner()).buildExecutionPlan(WEBAPP, { vhostMode: true });
    expect(plan.arguments[plan.arguments.indexOf("-H") + 1]).toBe("Host: FUZZ.example.com");
    expect(plan.arguments).not.toContain("https://example.com/FUZZ");
    const plain = await new FfufAdapter(new FixtureToolRunner()).buildExecutionPlan(WEBAPP, {});
    expect(plain.arguments).not.toContain("-H");
  });

  it("a user can never inject a wordlist PATH — only registered ids resolve (§11)", async () => {
    const adapter = new FfufAdapter(new FixtureToolRunner());
    await expect(adapter.buildExecutionPlan(WEBAPP, { wordlistId: "/etc/passwd" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    await expect(adapter.buildExecutionPlan(WEBAPP, { wordlistId: "../seclists/big.txt" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    await expect(adapter.buildExecutionPlan(WEBAPP, { wordlistId: "does-not-exist" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    const plan = await adapter.buildExecutionPlan(WEBAPP, { wordlistId: "parameter-names" });
    expect(plan.arguments).toContain("/wordlists/builtin/parameter-names.txt");
    // And there is no config key that could carry a path at all:
    await expect(adapter.validateConfiguration({ wordlistPath: "/tmp/x" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    await expect(adapter.validateConfiguration({ command: "ffuf ..." })).rejects.toBeInstanceOf(AdapterConfigurationError);
  });

  it("rate/concurrency clamps: schema refuses above-cap, plan clamps anyway (§15)", async () => {
    const adapter = new FfufAdapter(new FixtureToolRunner());
    await expect(adapter.validateConfiguration({ rateLimit: 500 })).rejects.toBeInstanceOf(AdapterConfigurationError);
    const plan = await adapter.buildExecutionPlan(WEBAPP, { rateLimit: 3 });
    expect(plan.arguments[plan.arguments.indexOf("-rate") + 1]).toBe("3"); // lower honoured
  });

  it("feroxbuster depth is hard-capped at 4 and rate-limited (§4)", async () => {
    const adapter = new FeroxbusterAdapter(new FixtureToolRunner());
    await expect(adapter.validateConfiguration({ depth: 9 })).rejects.toBeInstanceOf(AdapterConfigurationError);
    const plan = await adapter.buildExecutionPlan(WEBAPP, { depth: 4 });
    expect(plan.arguments[plan.arguments.indexOf("--depth") + 1]).toBe("4");
    expect(plan.arguments[plan.arguments.indexOf("--rate-limit") + 1]).toBe("10");
    expect(plan.arguments).not.toContain("--extract-links");
  });

  it("gobuster exposes dir mode ONLY (§5)", async () => {
    const plan = await new GobusterAdapter(new FixtureToolRunner()).buildExecutionPlan(WEBAPP, {});
    expect(plan.arguments[0]).toBe("dir");
    for (const mode of ["dns", "vhost", "s3", "gcs", "fuzz"]) expect(plan.arguments).not.toContain(mode);
    expect(plan.arguments).not.toContain("-r");
  });

  it("wfuzz has exactly two predefined templates — no arbitrary payload surface (§6/§29)", async () => {
    const adapter = new WfuzzAdapter(new FixtureToolRunner());
    await expect(adapter.validateConfiguration({ template: "CUSTOM" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    await expect(adapter.validateConfiguration({ payload: "anything" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    const content = await adapter.buildExecutionPlan(WEBAPP, { template: "CONTENT", urls: ["https://example.com/search"] });
    expect(content.arguments[content.arguments.length - 1]).toBe("https://example.com/search/FUZZ");
    const param = await adapter.buildExecutionPlan(WEBAPP, { template: "PARAMETER", urls: ["https://example.com/search"] });
    expect(param.arguments[param.arguments.length - 1]).toBe("https://example.com/search/?FUZZ=dsrclone");
    expect(param.arguments[param.arguments.indexOf("-z") + 1]).toBe("file,/wordlists/builtin/parameter-names.txt");
  });

  it("arjun feeds ONE prioritized endpoint and runs stable (§7/§28)", async () => {
    const plan = await new ArjunAdapter(new FixtureToolRunner()).buildExecutionPlan(WEBAPP, {
      urls: ["https://example.com/assets/app.js", "https://example.com/about", "https://example.com/api/users"],
    });
    expect(plan.arguments[plan.arguments.indexOf("-u") + 1]).toBe("https://example.com/api/users");
    expect(plan.arguments).toContain("--stable");
  });

  it("technology hints surface the technology list as an additional reference (§13)", async () => {
    const adapter = new FfufAdapter(new FixtureToolRunner());
    const resolved = adapter.wordlistPlan({ technologies: ["WordPress"], wordlistProfile: "STANDARD" });
    expect(resolved.primary.id).toBe("common-directories-standard");
    expect(resolved.additional.map((w) => w.id)).toEqual(["wordpress-routes"]);
  });
});

describe("health + fixture execution (§56–§58)", () => {
  it("missing binaries report UNAVAILABLE honestly", async () => {
    const adapter = new FfufAdapter(new FixtureToolRunner({}));
    expect(await adapter.healthCheck()).toMatchObject({ status: "UNAVAILABLE" });
    await expect(adapter.execute(await adapter.buildExecutionPlan(WEBAPP, {}))).rejects.toThrow(/not available/);
  });

  it("fixture run: ffuf executes → endpoints with classification metadata, zero findings", async () => {
    const runner = new FixtureToolRunner({ ffuf: { stdout: F.FFUF_JSON, version: "2.1.0" } });
    const adapter = new FfufAdapter(runner);
    expect((await adapter.healthCheck()).status).toBe("HEALTHY");
    const normalized = await adapter.normalize(await adapter.parse((await adapter.execute(await adapter.buildExecutionPlan(WEBAPP, {}))).rawOutput ?? ""));
    expect(normalized.endpoints).toHaveLength(9);
    expect(normalized.findings).toEqual([]);
  });

  it("fixture run: gobuster parses with the plan's base URL", async () => {
    const runner = new FixtureToolRunner({ gobuster: { stdout: F.GOBUSTER_TEXT, version: "3.6" } });
    const adapter = new GobusterAdapter(runner);
    const plan = await adapter.buildExecutionPlan(WEBAPP, {});
    const normalized = await adapter.normalize(await adapter.parse((await adapter.execute(plan)).rawOutput ?? ""));
    expect(normalized.endpoints.map((e) => e.url)).toContain("https://example.com/server-status");
  });

  it("fixture run: arjun + wfuzz through the full lifecycle", async () => {
    const arjun = new ArjunAdapter(new FixtureToolRunner({ arjun: { stdout: F.ARJUN_JSON } }));
    const aNorm = await arjun.normalize(await arjun.parse((await arjun.execute(await arjun.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/search"] }))).rawOutput ?? ""));
    expect(aNorm.parameters).toHaveLength(5);
    const wfuzz = new WfuzzAdapter(new FixtureToolRunner({ wfuzz: { stdout: F.WFUZZ_JSON, version: "2.4.5" } }));
    const wNorm = await wfuzz.normalize(await wfuzz.parse((await wfuzz.execute(await wfuzz.buildExecutionPlan(WEBAPP, { template: "PARAMETER", urls: ["https://example.com/search"] }))).rawOutput ?? ""));
    expect(wNorm.parameters!.map((p) => p.name).sort()).toEqual(["id", "sort"]);
    expect(createWebDiscoveryAdapters(new FixtureToolRunner())).toHaveLength(5);
  });
});
