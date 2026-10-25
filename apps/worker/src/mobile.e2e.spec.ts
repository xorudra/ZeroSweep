import { describe, expect, it } from "vitest";
import {
  FIXTURE_APKTOOL_OUTPUT, FIXTURE_BUILD_HASH, FIXTURE_GHIDRA_REPORT, FIXTURE_JADX_OUTPUT,
  FIXTURE_MOBSF_REPORT, FIXTURE_SECRET_VALUE, FixtureToolRunner, LocalEchoAdapter,
  MockSecurityAdapter, ToolRegistry, createFixtureMobileDeps, createMobileAdapters,
  fixtureAnalysisArtifacts, mobileHealthBySlug, planMobileRetest, type FixtureResponse,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";
import { stampMobileFindings } from "./executors/mobile-stamp";
import type { ProcessedFinding } from "./executors/result-processor";

/**
 * Prompt 17 end-to-end scenarios (§103–§115): the real mobile
 * adapters + platform stages run the full pipeline over RECORDED
 * fixture outputs for the synthetic com.example.app. No real app is
 * analyzed, no binary is executed, no device or network is touched:
 * static analysis is the default; dynamic stages run only against
 * the fixture lab transport with an approved session; the planted
 * FAKE secret's value exists in NO persisted record (§106).
 */

const TOOL_FIXTURES: Record<string, FixtureResponse> = {
  // FixtureToolRunner keys fixtures by EXECUTABLE name.
  jadx: { stdout: FIXTURE_JADX_OUTPUT, version: "1.5.1" },
  apktool: { stdout: FIXTURE_APKTOOL_OUTPUT, version: "2.9.3" },
  analyzeHeadless: { stdout: FIXTURE_GHIDRA_REPORT, version: "11.3" },
};

type MobileFixtures = InstanceType<typeof FakeStore>["mobileFixtures"];

type MobileProfile = "MOBILE_STATIC_BASELINE" | "MOBILE_STATIC_COMPREHENSIVE" | "MOBILE_SECRETS_ONLY" | "MOBILE_BINARY_ANALYSIS" | "MOBILE_DYNAMIC_CONTROLLED" | "MOBILE_FULL_CONTROLLED" | "MOBILE";

function makeWorld(profile: MobileProfile, opts: {
  mobileFixtures?: MobileFixtures;
  workerCapabilities?: string[];
  scannerBySlug?: Record<string, { instanceId: string }>;
} = {}) {
  const deps = createFixtureMobileDeps();
  const planAdapters = createMobileAdapters(new FixtureToolRunner(TOOL_FIXTURES), deps);
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  for (const a of planAdapters) planRegistry.register(a);
  const health = mobileHealthBySlug(planAdapters, deps);
  // Connectors/lab adapters resolve per-instance/per-session at
  // execute time (mirrors the plan posture of prior families).
  health.mobsf = "HEALTHY";
  health.adb = "HEALTHY";
  health.mitmproxy = "HEALTHY";
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: health,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "MOBILE_APP",
    networkTarget: {
      targetValue: "com.example.app", targetHost: "com.example.app",
      scope: { includeHosts: ["com.example.app"], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    },
    scannerBySlug: opts.scannerBySlug ?? { mobsf: { instanceId: "fixture-mobsf-1" } },
    mobileFixtures: opts.mobileFixtures ?? {
      applicationId: "mobile-app-1", applicationRef: "com.example.app",
      platform: "ANDROID", environment: "PRODUCTION",
      buildId: "mobile-build-1", buildHash: FIXTURE_BUILD_HASH,
      artifactReference: "fixture://mobile-build-1.apk",
      analysisArtifacts: fixtureAnalysisArtifacts(),
    },
  });
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createMobileAdapters(new FixtureToolRunner(TOOL_FIXTURES), deps)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, {
    workerCapabilities: opts.workerCapabilities ?? ["MOBILE_STATIC_ANALYSIS"],
  });
  return { store, executor, dag: new DagRunner(store, executor) };
}

describe("Prompt 17 E2E — MOBILE_STATIC_BASELINE over the fixture app (§104)", () => {
  it("intakes, extracts, analyzes statically, correlates, gates and reports — fixture-only", async () => {
    const { store, dag } = makeWorld("MOBILE_STATIC_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.events.some((e) => e.type === "mobile.build_validated")).toBe(true);
    expect(store.events.some((e) => e.type === "mobile.scan_completed")).toBe(true);
    expect(store.events.some((e) => e.type === "mobile.metadata_extracted")).toBe(true);

    // Inventory (§20–§33): manifest facts persisted on the build.
    const permissionNames = store.mobileData.permissions.map((p) => p.name);
    expect(permissionNames).toContain("android.permission.CAMERA");
    expect(store.mobileData.permissions.find((p) => p.name.endsWith("CAMERA"))?.classification).toBe("DANGEROUS");
    expect(store.mobileData.components.some((c) => c.name.endsWith(".MainActivity") && c.exported)).toBe(true);
    expect(store.mobileData.deepLinks.some((l) => l.host === "app.example.com")).toBe(true);
    expect(store.mobileData.signing.some((s) => s.debug === true)).toBe(true);

    // Endpoints (§29/§30): extracted, classified DISCOVERED_REFERENCE.
    expect(store.mobileData.endpoints.length).toBeGreaterThan(0);
    expect(store.mobileData.endpoints.every((e) => e.classification === "DISCOVERED_REFERENCE")).toBe(true);

    // Findings (§49): the planted issues across sources, all stamped
    // with the §50 mobile identity.
    const ruleIds = new Set(store.findings.map((f) => f.ruleId));
    expect(ruleIds.has("MOBILE_DEBUGGABLE_BUILD")).toBe(true);
    expect(ruleIds.has("MOBILE_HARDCODED_SECRET")).toBe(true);
    expect(ruleIds.has("MOBILE_WEBVIEW_JS_BRIDGE")).toBe(true);
    expect(ruleIds.has("MOBILE_CLEARTEXT_ENABLED")).toBe(true);
    for (const f of store.findings.filter((x) => x.mobileFindingType)) {
      expect(f.mobileBuildHash).toBe(FIXTURE_BUILD_HASH);
      expect(f.mobilePlatform).toBe("ANDROID");
      expect(f.crossBuildFingerprint).toMatch(/^[a-f0-9]{64}$/);
    }

    // Correlation (§51): canonical findings ≤ raw findings, sources merged.
    expect(store.correlatedFindings.length).toBeGreaterThan(0);
    expect(store.correlatedFindings.length).toBeLessThanOrEqual(store.findings.length);

    // MASVS assessments + the mobile quality gate (§48/§90).
    expect(store.controlAssessments.some((a) => a.frameworkKey === "OWASP_MASVS")).toBe(true);
    expect(store.mobileGateRecord).not.toBeNull();

    // §106: the planted FAKE secret value exists in NO output record.
    const visible = JSON.stringify({ findings: store.findings, correlated: store.correlatedFindings, events: store.events, mobileData: store.mobileData });
    expect(visible).not.toContain(FIXTURE_SECRET_VALUE);
  });

  it("an unregistered build fails intake honestly — NOT_CONFIGURED, never fabricated (§105)", async () => {
    const { store, dag } = makeWorld("MOBILE_STATIC_BASELINE", { mobileFixtures: {} });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.events.some((e) => e.type === "policy.denied" && (e.payload as { reasonCode?: string }).reasonCode === "MOBILE_BUILD_NOT_CONFIGURED")).toBe(true);
    expect(store.findings).toHaveLength(0);
  });

  it("without a registered MobSF instance the connector is denied; CLI adapters still run (§14)", async () => {
    const { store, dag } = makeWorld("MOBILE_STATIC_BASELINE", { scannerBySlug: {} });
    const result = await dag.run("scan-1");
    // One denied connector degrades the scan to PARTIAL (§55) — the
    // governed CLI adapters' evidence still lands, nothing is faked.
    expect(result.status).toBe("PARTIAL");
    expect(store.findings.some((f) => f.sourceTool === "jadx")).toBe(true);
    expect(store.findings.some((f) => f.sourceTool === "mobsf")).toBe(false);
  });
});

describe("Prompt 17 E2E — capability separation + controlled dynamic (§107–§113)", () => {
  it("a worker without MOBILE_STATIC_ANALYSIS collects no tool findings (§10)", async () => {
    const { store, dag } = makeWorld("MOBILE_STATIC_BASELINE", { workerCapabilities: [] });
    await dag.run("scan-1");
    expect(store.findings.some((f) => ["jadx", "apktool", "mobsf", "ghidra"].includes(f.sourceTool))).toBe(false);
    expect(store.events.some((e) => e.type === "policy.denied" && (e.payload as { reasonCode?: string }).reasonCode === "UNAVAILABLE_FOR_WORKER")).toBe(true);
  });

  it("dynamic stages are skipped honestly on a baseline profile — no session, no device (§58)", async () => {
    const { store, dag } = makeWorld("MOBILE_DYNAMIC_CONTROLLED", {
      workerCapabilities: ["MOBILE_STATIC_ANALYSIS"],
      mobileFixtures: {
        applicationId: "mobile-app-1", applicationRef: "com.example.app",
        platform: "ANDROID", environment: "PRODUCTION",
        buildId: "mobile-build-1", buildHash: FIXTURE_BUILD_HASH,
        analysisArtifacts: fixtureAnalysisArtifacts(),
      },
    });
    const result = await dag.run("scan-1");
    // Dynamic adapters are denied on a static-only worker: the scan
    // completes its static chain and reports PARTIAL — dynamic work
    // is honestly absent, never simulated (§58).
    expect(result.status).toBe("PARTIAL");
    expect(store.events.some((e) => e.type === "policy.denied" && (e.payload as { reasonCode?: string }).reasonCode === "UNAVAILABLE_FOR_WORKER")).toBe(true);
    expect(store.findings.some((f) => f.sourceTool === "adb" || f.sourceTool === "mitmproxy")).toBe(false);
  });

  it("an approved lab session on a dynamic worker runs; runtime cleartext CONFIRMS the static finding (§88)", async () => {
    const { store, dag } = makeWorld("MOBILE_DYNAMIC_CONTROLLED", {
      workerCapabilities: ["MOBILE_STATIC_ANALYSIS", "MOBILE_DYNAMIC_ANALYSIS"],
      mobileFixtures: {
        applicationId: "mobile-app-1", applicationRef: "com.example.app",
        platform: "ANDROID", environment: "PRODUCTION",
        buildId: "mobile-build-1", buildHash: FIXTURE_BUILD_HASH,
        analysisArtifacts: fixtureAnalysisArtifacts(),
        deviceId: "lab-emulator-1", dynamicSessionId: "dyn-1", dynamicSessionApproved: true,
        trafficSessionId: "fixture-traffic-1",
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.findings.some((f) => f.ruleId === "MOBILE_RUNTIME_CLEARTEXT_TRAFFIC")).toBe(true);
    const confirmed = store.correlatedFindings.find((f) => f.ruleId === "MOBILE_CLEARTEXT_ENABLED");
    expect(confirmed?.dynamicConfirmed).toBe(true);
  });

  it("an active kill switch terminates dynamic work (§92)", async () => {
    const { store, dag } = makeWorld("MOBILE_DYNAMIC_CONTROLLED", {
      workerCapabilities: ["MOBILE_STATIC_ANALYSIS", "MOBILE_DYNAMIC_ANALYSIS"],
      mobileFixtures: {
        applicationId: "mobile-app-1", applicationRef: "com.example.app",
        platform: "ANDROID", environment: "PRODUCTION",
        buildId: "mobile-build-1", buildHash: FIXTURE_BUILD_HASH,
        analysisArtifacts: fixtureAnalysisArtifacts(),
        deviceId: "lab-emulator-1", dynamicSessionId: "dyn-1", dynamicSessionApproved: true,
        trafficSessionId: "fixture-traffic-1",
        killSwitches: [{ level: "WORKSPACE", active: true }],
      },
    });
    await dag.run("scan-1");
    expect(store.events.some((e) => e.type === "policy.denied" && (e.payload as { reasonCode?: string }).reasonCode === "KILL_SWITCH_ACTIVE")).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "MOBILE_RUNTIME_CLEARTEXT_TRAFFIC")).toBe(false);
  });

  it("Frida/Objection are not executable and no stage can select them (§69–§75)", () => {
    expect(EXECUTABLE_SLUGS).not.toContain("frida");
    expect(EXECUTABLE_SLUGS).not.toContain("objection");
    expect(EXECUTABLE_SLUGS).toEqual(expect.arrayContaining(["mobsf", "jadx", "apktool", "ghidra", "adb", "mitmproxy"]));
  });
});

describe("Prompt 17 E2E — cross-build retest identity (§89/§51)", () => {
  it("the cross-build key is stable across builds while the canonical fingerprint changes", () => {
    const base: ProcessedFinding = {
      title: "Cleartext traffic permitted", description: "d", severity: "HIGH", confidence: 0.85,
      fingerprint: "raw", isMock: false, sourceTool: "mobile-platform-analysis",
      toolExecutionId: "e1", evidenceSummary: "", sources: ["mobile-platform-analysis"],
      evidenceRows: [], references: [], ruleId: "MOBILE_CLEARTEXT_ENABLED", cwe: "CWE-319",
      mobileComponent: "network-security-config",
    };
    const identityA = { applicationId: "mobile-app-1", applicationRef: "com.example.app", buildId: "b-a", buildHash: "a".repeat(64), platform: "ANDROID" as const };
    const identityB = { ...identityA, buildId: "b-b", buildHash: "b".repeat(64) };
    const [a] = stampMobileFindings([base], identityA);
    const [b] = stampMobileFindings([base], identityB);
    expect(a!.fingerprint).not.toBe(b!.fingerprint);
    expect(a!.crossBuildFingerprint).toBe(b!.crossBuildFingerprint);
    expect(planMobileRetest({ ruleId: "MOBILE_CLEARTEXT_ENABLED", sourceTool: "mobile-platform-analysis" }).adapterSlug).toBe("apktool");
    expect(planMobileRetest({ mobileFindingType: "MOBILE_BINARY_FINDING" }).adapterSlug).toBe("ghidra");
  });
});
