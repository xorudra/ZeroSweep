import { describe, expect, it } from "vitest";
import { FixtureToolRunner } from "../recon/runner";
import { ToolRegistry } from "../registry/registry";
import { NiktoAdapter, NucleiAdapter, SslyzeAdapter, TestsslAdapter, tlsServicesFor } from "./adapters-vuln";
import { NIKTO_JSON, NUCLEI_JSONL, SSLYZE_JSON, TESTSSL_JSON } from "./fixtures";
import { createVulnAdapters, registerVulnAdapters, VULN_SLUGS, vulnHealthBySlug } from "./registry";
import type { ParsedVuln } from "./parsers-vuln";

const WEBAPP = { type: "WEB_APPLICATION" as const, value: "https://example.com", host: "example.com" };

/**
 * Adapter tests (Prompt 7 §2/§58): the four adapters run the full SDK
 * lifecycle against a FixtureToolRunner — recorded output only, no binary
 * executes, no network is touched.
 */
describe("vuln adapter registration + health (§49)", () => {
  it("all four adapters register and resolve by capability", () => {
    const registry = new ToolRegistry();
    const adapters = registerVulnAdapters(registry, new FixtureToolRunner());
    expect(adapters.map((a) => a.metadata.slug).sort()).toEqual([...VULN_SLUGS].sort());
    expect(registry.byCapability("TLS_ANALYSIS").map((a) => a.metadata.slug).sort()).toEqual(["sslyze", "testssl"]);
    expect(registry.byCapability("VULNERABILITY_SCANNING").map((a) => a.metadata.slug).sort()).toEqual(["nikto", "nuclei"]);
  });

  it("absent binaries health-report UNAVAILABLE — never faked (§49)", () => {
    const adapters = createVulnAdapters(new FixtureToolRunner());
    expect(Object.values(vulnHealthBySlug(adapters))).toEqual(["UNAVAILABLE", "UNAVAILABLE", "UNAVAILABLE", "UNAVAILABLE"]);
  });
});

describe("NucleiAdapter (§3–§8)", () => {
  it("plans governed templates only: collection path + explicit exclusions, rate/concurrency clamped, no shell", async () => {
    const adapter = new NucleiAdapter(new FixtureToolRunner({ nuclei: { stdout: NUCLEI_JSONL, version: "3.3.0" } }));
    const plan = await adapter.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/"], requestsPerSecond: 150, concurrency: 25 });
    const args = plan.arguments.join(" ");
    expect(args).toContain("/opt/dsrclone/nuclei-templates/governed");
    expect(args).toContain("-exclude-templates");
    expect(args).toContain("sqli-error-based"); // excluded by id
    expect(args).toContain("default-login-check");
    expect(args).toContain("-rate-limit 150"); // schema-capped maximum — nothing above it is a valid config
    expect(args).toContain("-concurrency 25");
    const defaulted = await adapter.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/"] });
    expect(defaulted.arguments.join(" ")).toContain("-rate-limit 50"); // conservative platform default (§52)
    expect(args).toContain("-no-interactsh");
    expect(plan.stdin).toContain("https://example.com/");
  });

  it("normalize() drops findings from non-automatable templates and counts the exclusion", async () => {
    const adapter = new NucleiAdapter(new FixtureToolRunner({ nuclei: { stdout: NUCLEI_JSONL } }));
    await adapter.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/"] });
    const parsed = (await adapter.parse(NUCLEI_JSONL)) as ParsedVuln;
    expect(parsed.findings).toHaveLength(5); // parser is faithful; policy drops at normalize
    const normalized = await adapter.normalize(parsed);
    const ids = normalized.findings.map((f) => (f as { templateId?: string }).templateId);
    expect(ids).not.toContain("sqli-error-based"); // INTRUSIVE
    expect(ids).not.toContain("brand-new-check-2099"); // unknown -> REVIEW_REQUIRED, unapproved
    expect(ids).toContain("http-missing-security-headers");
    expect(normalized.metrics.policyExcludedTemplates).toBe(2);
  });

  it("a raw-command config key is rejected by schema validation, always", async () => {
    const adapter = new NucleiAdapter(new FixtureToolRunner());
    await expect(adapter.buildExecutionPlan(WEBAPP, { command: "nuclei -u https://evil.example" } as never))
      .rejects.toThrow(/command|not a declared input/i);
  });
});

describe("NiktoAdapter (§9)", () => {
  it("runs the lifecycle against fixture output and normalizes findings", async () => {
    const adapter = new NiktoAdapter(new FixtureToolRunner({ nikto: { stdout: NIKTO_JSON, version: "2.5.0" } }));
    const plan = await adapter.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/"] });
    expect(plan.arguments).toContain("-maxtime");
    const exec = await adapter.execute(plan);
    const parsed = await adapter.parse(exec.rawOutput ?? "");
    const normalized = await adapter.normalize(parsed);
    expect(normalized.findings.length).toBe(4);
    expect(normalized.findings.every((f) => f.sourceTool === "nikto")).toBe(true);
  });
});

describe("TLS adapters (§11–§13)", () => {
  it("selects TLS services from https URLs only, capped, never every port", () => {
    const services = tlsServicesFor(WEBAPP, { urls: ["http://example.com/a", "https://example.com/x", "https://api.example.com:8443/y"] }, 25);
    expect(services).toEqual(["example.com:443", "api.example.com:8443"]);
    expect(tlsServicesFor(WEBAPP, {}, 25)).toEqual(["example.com:443"]);
    const many = Array.from({ length: 50 }, (_, i) => `https://h${i}.example.com/`);
    expect(tlsServicesFor(WEBAPP, { urls: many }, 5)).toHaveLength(5);
  });

  it("testssl + sslyze lifecycles produce correlatable TLS findings", async () => {
    const t = new TestsslAdapter(new FixtureToolRunner({ "testssl.sh": { stdout: TESTSSL_JSON, version: "3.2" } }));
    const tExec = await t.execute(await t.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/"] }));
    const tNorm = await t.normalize(await t.parse(tExec.rawOutput ?? ""));
    expect(tNorm.findings.some((f) => (f as { vulnClass?: string }).vulnClass === "TLS_WEAK_PROTOCOL")).toBe(true);

    const s = new SslyzeAdapter(new FixtureToolRunner({ sslyze: { stdout: SSLYZE_JSON, version: "6.0" } }));
    const sExec = await s.execute(await s.buildExecutionPlan(WEBAPP, { urls: ["https://example.com/"] }));
    const sNorm = await s.normalize(await s.parse(sExec.rawOutput ?? ""));
    expect(sNorm.findings).toHaveLength(1);
    expect((sNorm.findings[0] as { vulnClass?: string }).vulnClass).toBe("TLS_WEAK_PROTOCOL");
  });
});
