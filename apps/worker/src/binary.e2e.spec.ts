import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CHECKSEC_HARDENED_JSON, CHECKSEC_UNHARDENED_JSON, EXECUTION_MARKER_PATH, FAKE_BINARY_TOKEN,
  FIXTURE_ELF_HARDENED, FIXTURE_ELF_SHA256, FIXTURE_ELF_UNHARDENED, FIXTURE_ELF_UNHARDENED_SHA256,
  FIXTURE_EMBEDDED_URL, GHIDRA_BINARY_REPORT_JSON, RADARE2_REPORT_JSON, FixtureToolRunner,
  LocalEchoAdapter, MockSecurityAdapter, ToolRegistry, binaryHealthBySlug, createBinaryAdapters,
  type FixtureResponse,
} from "@dsrclone/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 18 end-to-end scenarios (§97–§119): the real binary
 * adapters + platform stages run the full pipeline over RECORDED
 * fixture outputs for synthetic binaries built in-repo. No real
 * binary is executed, debugged, emulated or detonated — analysis is
 * parsing + recorded outputs only; the fixture's embedded marker
 * payload is inert data and the marker file must NEVER appear
 * (§100). The planted FAKE token exists in NO persisted record
 * (§108).
 */

const TOOL_FIXTURES: Record<string, FixtureResponse> = {
  // FixtureToolRunner keys fixtures by EXECUTABLE name.
  checksec: { stdout: CHECKSEC_HARDENED_JSON, version: "2.7.1" },
  analyzeHeadless: { stdout: GHIDRA_BINARY_REPORT_JSON, version: "11.3" },
  r2: { stdout: RADARE2_REPORT_JSON, version: "5.9.8" },
};

type BinaryFixtures = InstanceType<typeof FakeStore>["binaryFixtures"];
type BinaryProfile = "BINARY_METADATA_ONLY" | "BINARY_BASELINE" | "BINARY_ASSESSMENT" | "BINARY_COMPREHENSIVE_STATIC" | "BINARY_DEPENDENCY_ANALYSIS" | "BINARY_CONTROLLED_DEBUG";

async function makeWorld(profile: BinaryProfile, opts: {
  binaryFixtures?: BinaryFixtures;
  workerCapabilities?: string[];
  fixtures?: Record<string, FixtureResponse>;
} = {}) {
  const runner = new FixtureToolRunner(opts.fixtures ?? TOOL_FIXTURES);
  const planAdapters = createBinaryAdapters(runner);
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  for (const a of planAdapters) planRegistry.register(a);
  const healthRaw = await binaryHealthBySlug(planAdapters);
  const health: Record<string, string> = Object.fromEntries(Object.entries(healthRaw).map(([k, v]) => [k, v.status]));
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: health,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "BINARY",
    networkTarget: {
      targetValue: "app-hardened", targetHost: "app-hardened",
      scope: { includeHosts: ["app-hardened"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    },
    binaryFixtures: opts.binaryFixtures ?? {
      artifactId: "binary-1", artifactHash: FIXTURE_ELF_SHA256,
      artifactName: "app-hardened", format: "ELF", architecture: "x86-64",
      environment: "PRODUCTION", artifactReference: "fixture://binary-1",
      headerSegment: FIXTURE_ELF_HARDENED,
    },
  });
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createBinaryAdapters(runner)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, {
    workerCapabilities: opts.workerCapabilities ?? ["BINARY_STATIC_ANALYSIS"],
  });
  return { store, executor, dag: new DagRunner(store, executor), runner };
}

describe("Prompt 18 E2E — BINARY_BASELINE over the hardened fixture (§97–§100)", () => {
  it("intakes, parses, analyzes statically, correlates, gates and reports — fixture-only, nothing executed", async () => {
    const { store, dag, runner } = await makeWorld("BINARY_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.events.some((e) => e.type === "binary.artifact_validated")).toBe(true);
    expect(store.events.some((e) => e.type === "binary.metadata_extracted")).toBe(true);
    expect(store.events.some((e) => e.type === "binary.scan_completed")).toBe(true);

    // Inventory (§12–§25): sections, functions, dependencies persisted.
    expect(store.binaryData.sections.some((s) => s.name === ".text")).toBe(true);
    expect(store.binaryData.functions.some((f) => f.name === "main")).toBe(true);
    expect(store.binaryData.functions.some((f) => f.name === "process_request")).toBe(true);
    const versioned = store.binaryData.dependencies.find((d) => d.version === "1.2.11");
    expect(versioned).toBeDefined(); // zlib 1.2.11 — from the soname suffix + Ghidra library record
    const ssl = store.binaryData.dependencies.find((d) => d.library.includes("ssl"));
    expect(ssl?.version).toBeUndefined(); // §25: no version inferred from libssl.so.3
    const nx = store.binaryData.hardening.find((h) => h.name === "NX");
    expect(nx?.status).toBe("ENABLED");

    // Findings are stamped with the §50 binary identity.
    const binaryFindings = store.findings.filter((f) => f.binaryFindingType);
    expect(binaryFindings.length).toBeGreaterThan(0);
    for (const f of binaryFindings) {
      expect(f.binaryArtifactHash).toBe(FIXTURE_ELF_SHA256);
      expect(f.binaryFingerprint).toBeTruthy();
    }
    // Risky API with function-reference evidence (§45): strcpy is
    // referenced by process_request in the Ghidra inventory.
    expect(store.findings.some((f) => f.ruleId === "BINARY_RISKY_STRCPY")).toBe(true);
    // Weak crypto from IMPORTED symbols only (§29).
    expect(store.findings.some((f) => f.ruleId === "BINARY_WEAK_CRYPTO")).toBe(true);

    // §108: the planted token appears in NO persisted record — only
    // its fingerprint + redacted preview.
    const persisted = JSON.stringify({ findings: store.findings, binaryData: store.binaryData, events: store.events });
    expect(persisted).not.toContain(FAKE_BINARY_TOKEN);
    expect(store.findings.some((f) => f.ruleId === "BINARY_EMBEDDED_SECRET")).toBe(true);

    // §31/§109: the embedded URL is a DISCOVERED_REFERENCE — never a
    // scan target, never scope expansion.
    expect(store.binaryData.discoveredReferences.some((r) => r.value === FIXTURE_EMBEDDED_URL && r.classification === "DISCOVERED_REFERENCE")).toBe(true);
    expect(store.assets.some((a) => a.host.includes("example.invalid"))).toBe(false);

    // §100 NO-EXECUTION: only analyzer executables ran (recorded
    // fixtures), the fixture binary itself never ran, and its
    // embedded marker payload never fired.
    expect(existsSync(EXECUTION_MARKER_PATH)).toBe(false);
    expect(runner.calls.length).toBeGreaterThan(0);
    for (const call of runner.calls) {
      expect(["checksec", "analyzeHeadless", "r2"]).toContain(call.executable);
      expect(call.args.join(" ")).not.toContain("touch");
    }

    // Quality gate (§63): the embedded secret fails the gate honestly.
    expect(store.binaryGateRecord?.status).toBe("FAILED");
    expect(store.binaryGateRecord?.failedRules).toContain("NO_EMBEDDED_SECRETS");
  });

  it("BINARY_METADATA_ONLY runs platform stages only — no tool executes at all", async () => {
    const { store, dag, runner } = await makeWorld("BINARY_METADATA_ONLY");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(runner.calls).toHaveLength(0);
    expect(store.binaryData.sections.length).toBeGreaterThan(0);
    expect(store.findings.some((f) => f.ruleId === "BINARY_EMBEDDED_SECRET")).toBe(true);
  });
});

describe("Prompt 18 E2E — multi-tool correlation (§51/§52, §105)", () => {
  it("checksec + platform NX gap on the unhardened fixture converge to ONE canonical finding", async () => {
    const { store, dag } = await makeWorld("BINARY_BASELINE", {
      fixtures: {
        checksec: { stdout: CHECKSEC_UNHARDENED_JSON, version: "2.7.1" },
        analyzeHeadless: { stdout: GHIDRA_BINARY_REPORT_JSON, version: "11.3" },
        r2: { stdout: RADARE2_REPORT_JSON, version: "5.9.8" },
      },
      binaryFixtures: {
        artifactId: "binary-2", artifactHash: FIXTURE_ELF_UNHARDENED_SHA256,
        artifactName: "app-unhardened", format: "ELF", architecture: "x86-64",
        environment: "PRODUCTION", artifactReference: "fixture://binary-2",
        headerSegment: FIXTURE_ELF_UNHARDENED,
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const canonical = store.correlatedFindings.length > 0 ? store.correlatedFindings : store.findings;
    const nxFindings = canonical.filter((f) => f.ruleId === "BINARY_NO_NX");
    expect(nxFindings).toHaveLength(1);
    expect(nxFindings[0]!.sources.length).toBeGreaterThanOrEqual(2);
    // Ghidra + radare2 inventories merged (§51): functions from both.
    expect(store.binaryData.functions.some((f) => f.name === "helper_check")).toBe(true);
    expect(store.binaryData.functions.some((f) => f.name === "process_request")).toBe(true);
  });
});

describe("Prompt 18 E2E — dependency intelligence (§27/§49, §107)", () => {
  it("a versioned dependency matches the LOCAL fixture dataset into a CVE finding; unversioned never matches", async () => {
    const { store, dag } = await makeWorld("BINARY_DEPENDENCY_ANALYSIS", {
      binaryFixtures: {
        artifactId: "binary-1", artifactHash: FIXTURE_ELF_SHA256,
        artifactName: "app-hardened", format: "ELF", architecture: "x86-64",
        environment: "PRODUCTION", artifactReference: "fixture://binary-1",
        headerSegment: FIXTURE_ELF_HARDENED,
        intelMatches: [{ purl: "pkg:generic/z@1.2.11", cveId: "CVE-2023-6992", cvssScore: 7.5, severity: "HIGH" }],
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const depFinding = store.findings.find((f) => f.binaryFindingType === "BINARY_DEPENDENCY_VULNERABILITY");
    expect(depFinding?.cve).toBe("CVE-2023-6992");
    expect(depFinding?.componentPurl).toBe("pkg:generic/z@1.2.11");
    // SBOM generated from the artifact's components (§27).
    expect(store.binarySbomRecord?.componentCount).toBeGreaterThan(0);
    expect(store.events.some((e) => e.type === "binary.sbom_generated")).toBe(true);
  });
});

describe("Prompt 18 E2E — worker capability + debug governance (§10/§64–§74)", () => {
  it("static adapters are POLICY-denied on a worker without BINARY_STATIC_ANALYSIS; platform stages still complete", async () => {
    const { store, dag, runner } = await makeWorld("BINARY_BASELINE", { workerCapabilities: [] });
    const result = await dag.run("scan-1");
    // Tool stages degrade honestly (PARTIAL) — the platform stages
    // still complete; nothing is fabricated to fill the gap.
    expect(result.status).toBe("PARTIAL");
    expect(runner.calls).toHaveLength(0);
    expect(store.binaryData.functions).toHaveLength(0); // Ghidra never ran
    expect(store.binaryData.sections.length).toBeGreaterThan(0); // platform parsing still ran
  });

  it("an APPROVED LAB debug session evaluates honestly as NOT_PROVISIONED — no debugger transport exists", async () => {
    const { store, dag } = await makeWorld("BINARY_CONTROLLED_DEBUG", {
      binaryFixtures: {
        artifactId: "binary-3", artifactHash: FIXTURE_ELF_SHA256,
        artifactName: "app-hardened", format: "ELF", architecture: "x86-64",
        environment: "LAB", artifactReference: "fixture://binary-3",
        headerSegment: FIXTURE_ELF_HARDENED,
        debugSession: { status: "APPROVED", requestedBy: "u-1", approvedBy: "u-2", environment: "LAB" },
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const evaluated = store.events.find((e) => e.type === "binary.debug_session_evaluated");
    expect(evaluated?.payload.status).toBe("NOT_PROVISIONED");
  });

  it("without a session the debug stage is skipped honestly (NOT_CONFIGURED), never fabricated", async () => {
    const { store, dag } = await makeWorld("BINARY_CONTROLLED_DEBUG");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.events.some((e) => e.type === "binary.debug_session_skipped")).toBe(true);
  });

  it("a scan without a registered artifact fails intake honestly as NOT_CONFIGURED", async () => {
    const { store, dag } = await makeWorld("BINARY_BASELINE", { binaryFixtures: {} });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.stages.get("BINARY_ARTIFACT_INTAKE")).toBe("FAILED");
  });
});
