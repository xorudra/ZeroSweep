import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  NIKTO_JSON, NUCLEI_JSONL, SSLYZE_JSON, TESTSSL_JSON,
  createVulnAdapters, vulnHealthBySlug, type FixtureResponse,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 7 end-to-end scenarios (§61): the four vulnerability/TLS adapters
 * run the full pipeline (plan → gated execution → parse → normalize →
 * persist → NORMALIZATION → CORRELATION → RISK_ANALYSIS) against RECORDED
 * FIXTURE OUTPUT injected through the ToolRunner. No binary executes, no
 * network is touched, no live target exists.
 */

function vulnFixtures(): Record<string, FixtureResponse> {
  return {
    nuclei: { stdout: NUCLEI_JSONL, version: "3.3.0" },
    nikto: { stdout: NIKTO_JSON, version: "2.5.0" },
    "testssl.sh": { stdout: TESTSSL_JSON, version: "3.2" },
    sslyze: { stdout: SSLYZE_JSON, version: "6.0.0" },
  };
}

function makeWorld(profile: "WEB_BASELINE" | "WEB_COMPREHENSIVE") {
  const fixtures = vulnFixtures();
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  const planAdapters = createVulnAdapters(new FixtureToolRunner(fixtures));
  for (const a of planAdapters) planRegistry.register(a);
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: vulnHealthBySlug(planAdapters),
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "WEB_APPLICATION",
  });
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createVulnAdapters(new FixtureToolRunner(fixtures))) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store);
  return { store, dag: new DagRunner(store, executor) };
}

const VULN_TOOLS = ["nuclei", "nikto", "testssl", "sslyze"];

describe("Prompt 7 E2E — WEB_BASELINE (conservative vuln detection)", () => {
  it("runs nuclei + TLS adapters (no nikto), correlates TLS 1.0 across three tools, drops intrusive templates", async () => {
    const { store, dag } = makeWorld("WEB_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.stages.get("SAFE_VULNERABILITY_SCAN")).toBe("COMPLETED");
    expect(store.stages.get("CORRELATION")).toBe("COMPLETED");
    expect(store.stages.get("RISK_ANALYSIS")).toBe("COMPLETED");

    const executed = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executed).toEqual(expect.arrayContaining(["nuclei", "testssl", "sslyze"]));
    expect(executed).not.toContain("nikto"); // §50: baseline excludes Nikto

    // Raw persisted findings from the vuln tools: nuclei 3 kept (2 dropped
    // by template policy), testssl 3, sslyze 1.
    const raw = store.findings.filter((f) => VULN_TOOLS.includes(f.sourceTool));
    expect(raw).toHaveLength(7);
    expect(raw.some((f) => f.vulnClass === "GENERIC_VULNERABILITY" && f.sourceTool === "nuclei")).toBe(false);

    // Correlation: TLS 1.0 is ONE canonical finding with three sources.
    const canonical = store.correlatedFindings.filter((f) => f.vulnClass);
    const tls = canonical.find((f) => f.vulnClass === "TLS_WEAK_PROTOCOL")!;
    expect([...tls.sources].sort()).toEqual(["nuclei", "sslyze", "testssl"]);
    expect(tls.evidenceRows).toHaveLength(3); // every tool's evidence preserved
    expect(tls.riskScore).toBeGreaterThan(0);
    expect(store.events.some((e) => e.type === "finding.correlated")).toBe(true);
    expect(store.events.some((e) => e.type === "risk.calculated")).toBe(true);

    // Template governance is frozen into the execution record (§6):
    // SAFE templates selected, intrusive ones never selected.
    const nucleiExec = [...store.executions.values()].find((e) => e.adapterSlug === "nuclei")!;
    const metrics = nucleiExec.patch.metrics as { templatesSelected?: string[]; templateSnapshot?: { version?: string } };
    expect(metrics.templateSnapshot?.version).toBeTruthy();
    expect(metrics.templatesSelected).toContain("http-missing-security-headers");
    expect(metrics.templatesSelected).not.toContain("sqli-error-based");
    expect(metrics.templatesSelected).not.toContain("default-login-check");
  });

  it("produces zero findings from stages before SAFE_VULNERABILITY_SCAN (recon honesty, §47)", async () => {
    const { store, dag } = makeWorld("WEB_BASELINE");
    await dag.run("scan-1");
    const nonVuln = store.findings.filter((f) => !VULN_TOOLS.includes(f.sourceTool) && !f.isMock);
    expect(nonVuln).toHaveLength(0);
  });
});

describe("Prompt 7 E2E — WEB_COMPREHENSIVE (adds Nikto + approved review templates)", () => {
  it("runs all four adapters; missing-headers merges nuclei + nikto into one canonical finding", async () => {
    const { store, dag } = makeWorld("WEB_COMPREHENSIVE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const executed = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executed).toEqual(expect.arrayContaining(["nuclei", "nikto", "testssl", "sslyze"]));

    const raw = store.findings.filter((f) => VULN_TOOLS.includes(f.sourceTool));
    expect(raw).toHaveLength(11); // nuclei 3 + nikto 4 + testssl 3 + sslyze 1

    const canonical = store.correlatedFindings.filter((f) => f.vulnClass);
    const headers = canonical.find((f) => f.vulnClass === "MISSING_SECURITY_HEADERS" && f.endpoint === "https://example.com/")!;
    expect([...headers.sources].sort()).toEqual(["nikto", "nuclei"]);
    expect(headers.evidenceRows.length).toBeGreaterThanOrEqual(2);
    // Similar but distinct issues stay distinct (§60).
    expect(canonical.some((f) => f.vulnClass === "DIRECTORY_LISTING")).toBe(true);
    expect(canonical.some((f) => f.vulnClass === "COOKIE_NO_HTTPONLY")).toBe(true);
    expect(canonical.filter((f) => f.vulnClass === "TLS_WEAK_PROTOCOL")).toHaveLength(1);
  });
});
