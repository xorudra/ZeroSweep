import { describe, expect, it } from "vitest";
import {
  AIRCRACK_INFO_FIXTURE, FAKE_WIFI_PSK, FIXTURE_AP_ROGUE, FIXTURE_AP_WEP, FIXTURE_AP_WPA2,
  FIXTURE_AP_WPA3, FIXTURE_CORP_SSID, FIXTURE_STATION_MAC, HCX_SUMMARY_FIXTURE,
  KISMET_FIXTURE_JSON, TSHARK_WIRELESS_FIXTURE, FixtureToolRunner, LocalEchoAdapter,
  MockSecurityAdapter, ToolRegistry, createWirelessAdapters, wirelessHealthBySlug,
  type FixtureResponse,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 19 end-to-end scenarios (§94–§99): the real wireless
 * adapters + platform stages run the full pipeline over RECORDED
 * fixture outputs — a Kismet device export, a tshark field export,
 * an hcxpcapngtool summary and an aircrack-ng capture-info listing.
 * NOTHING transmits: the only executables ever invoked are the four
 * passive/offline ones, and the planted FAKE_WIFI_PSK exists in NO
 * persisted record (§67/§94). No real radio, sensor or capture is
 * involved.
 */

const TOOL_FIXTURES: Record<string, FixtureResponse> = {
  // FixtureToolRunner keys fixtures by EXECUTABLE name.
  kismet: { stdout: KISMET_FIXTURE_JSON, version: "2023.07.R1" },
  tshark: { stdout: TSHARK_WIRELESS_FIXTURE, version: "4.2.0" },
  hcxpcapngtool: { stdout: HCX_SUMMARY_FIXTURE, version: "6.3.4" },
  "aircrack-ng": { stdout: AIRCRACK_INFO_FIXTURE, version: "1.7" },
};

type WirelessFixtures = InstanceType<typeof FakeStore>["wirelessFixtures"];
type WirelessProfile = "WIRELESS_PASSIVE_BASELINE" | "WIRELESS_PASSIVE_COMPREHENSIVE" | "PCAP_ANALYSIS_ONLY" | "WIRELESS_COMPLIANCE" | "WIRELESS_LAB_VALIDATION";

const APPROVED_PROFILES = [{
  ssid: FIXTURE_CORP_SSID, bssid: FIXTURE_AP_WPA2, securityMode: "WPA2",
  authentication: "PSK", allowedChannels: [6], allowedBands: ["2.4GHZ"],
}];

async function makeWorld(profile: WirelessProfile, opts: {
  wirelessFixtures?: WirelessFixtures;
  workerCapabilities?: string[];
  fixtures?: Record<string, FixtureResponse>;
} = {}) {
  const runner = new FixtureToolRunner(opts.fixtures ?? TOOL_FIXTURES);
  const planAdapters = createWirelessAdapters(runner);
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  for (const a of planAdapters) planRegistry.register(a);
  const healthRaw = await wirelessHealthBySlug(planAdapters);
  const health: Record<string, string> = Object.fromEntries(Object.entries(healthRaw).map(([k, v]) => [k, v.status]));
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: health,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "WIRELESS_LAB",
    networkTarget: {
      targetValue: FIXTURE_CORP_SSID, targetHost: FIXTURE_CORP_SSID,
      scope: { includeHosts: [FIXTURE_CORP_SSID], excludeHosts: [], includeCidrs: [], allowedPorts: [], allowedPaths: [], excludedPaths: [] },
    },
    wirelessFixtures: opts.wirelessFixtures ?? {
      environmentId: "wl-env-1", environmentRef: FIXTURE_CORP_SSID, environmentKind: "CORPORATE",
      sensorRef: "sensor-1", sensorInterface: "wlan1",
      captureId: "capture-1", captureReference: "fixture://capture-1",
      approvedProfiles: APPROVED_PROFILES,
    },
  });
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createWirelessAdapters(runner)) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, {
    workerCapabilities: opts.workerCapabilities ?? ["WIRELESS_PASSIVE_ANALYSIS"],
  });
  return { store, executor, dag: new DagRunner(store, executor), runner };
}

describe("Prompt 19 E2E — WIRELESS_PASSIVE_BASELINE over recorded fixtures (§94)", () => {
  it("intakes, discovers passively, analyzes posture, gates and reports — nothing transmitted", async () => {
    const { store, dag, runner } = await makeWorld("WIRELESS_PASSIVE_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.events.some((e) => e.type === "wireless.environment_validated")).toBe(true);
    expect(store.events.some((e) => e.type === "wireless.scan_completed")).toBe(true);

    // Inventory (§6/§54): the corp WPA2 AP is ONE canonical row even
    // though the fixture export lists it once per sensor view.
    const aps = store.wirelessData.accessPoints;
    expect(aps.filter((a) => a.bssid === FIXTURE_AP_WPA2)).toHaveLength(1);
    expect(aps.some((a) => a.bssid === FIXTURE_AP_WEP && a.securityMode === "WEP")).toBe(true);
    expect(aps.some((a) => a.bssid === FIXTURE_AP_WPA3 && a.securityMode === "WPA3")).toBe(true);

    // Posture findings (§32/§44): WEP is a finding; the rogue suspect
    // (corp SSID on an unapproved BSSID, open) is SUSPICIOUS — never
    // labelled a confirmed evil twin.
    expect(store.findings.some((f) => f.wirelessBssid === FIXTURE_AP_WEP && f.wirelessFindingType === "WIRELESS_ENCRYPTION_FINDING")).toBe(true);
    const rogue = store.findings.find((f) => f.wirelessBssid === FIXTURE_AP_ROGUE && f.wirelessFindingType === "WIRELESS_ROGUE_AP_FINDING");
    expect(rogue).toBeDefined();
    expect(rogue?.wirelessRogueClassification).toBe("SUSPICIOUS");
    for (const f of store.findings.filter((x) => x.wirelessFindingType)) {
      expect(f.wirelessEnvironmentId).toBe("wl-env-1");
      expect(f.wirelessFingerprint).toBeTruthy();
    }

    // Privacy (§9/§90): the station is pseudonymized — its raw MAC
    // appears NOWHERE in persisted state.
    expect(store.wirelessData.stations.length).toBeGreaterThan(0);
    for (const s of store.wirelessData.stations) expect(s.addressFingerprint).toMatch(/^sta-[0-9a-f]{16}$/);

    // §67/§92/§94: the planted PSK and the raw station MAC exist in
    // NO persisted record; the hostile SSID survives only in its
    // sanitized form — terminal escapes stripped (§92), carried as
    // inert text data that the GUI renders escaped, never as markup.
    const persisted = JSON.stringify({ findings: store.findings, wireless: store.wirelessData, events: store.events });
    expect(persisted).not.toContain(FAKE_WIFI_PSK);
    expect(persisted).not.toContain(FIXTURE_STATION_MAC);
    expect(persisted).not.toContain("\\u001b");
    expect(persisted).not.toContain("[31m");
    const hostile = store.wirelessData.accessPoints.find((a) => a.bssid === "00:0b:86:66:77:88");
    expect(hostile?.ssid).toBe("<script>alert(1)</script>RED");
    expect(hostile?.ssid.length).toBeLessThanOrEqual(64);

    // §99: the ONLY executable invoked is kismet (passive export).
    expect(runner.calls.length).toBeGreaterThan(0);
    for (const call of runner.calls) expect(call.executable).toBe("kismet");

    // Gate (§60): WEP on the estate fails the wireless gate.
    expect(store.wirelessGateRecord?.status).toBe("FAILED");
    expect(store.wirelessGateRecord?.failedRules).toContain("NO_WEP");
  });

  it("refuses honestly when no wireless environment is registered (NOT_CONFIGURED)", async () => {
    const { store, dag, runner } = await makeWorld("WIRELESS_PASSIVE_BASELINE", { wirelessFixtures: {} });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("FAILED");
    expect(store.events.some((e) => e.type === "policy.denied" && (e.payload as { reasonCode?: string }).reasonCode === "WIRELESS_ENVIRONMENT_NOT_CONFIGURED")).toBe(true);
    expect(runner.calls).toHaveLength(0);
  });

  it("denies Kismet on a worker without WIRELESS_PASSIVE_ANALYSIS (§13/§14)", async () => {
    const { store, dag, runner } = await makeWorld("WIRELESS_PASSIVE_BASELINE", { workerCapabilities: [] });
    await dag.run("scan-1");
    expect(store.events.some((e) => e.type === "policy.denied" && (e.payload as { reasonCode?: string }).reasonCode === "UNAVAILABLE_FOR_WORKER")).toBe(true);
    expect(runner.calls.filter((c) => c.executable === "kismet")).toHaveLength(0);
    expect(store.wirelessData.accessPoints).toHaveLength(0);
  });
});

describe("Prompt 19 E2E — WIRELESS_PASSIVE_COMPREHENSIVE offline capture analysis (§89)", () => {
  it("runs tshark/hcxpcapngtool/aircrack-ng OFFLINE over the approved capture; material counted, never kept", async () => {
    const { store, dag, runner } = await makeWorld("WIRELESS_PASSIVE_COMPREHENSIVE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    const executables = [...new Set(runner.calls.map((c) => c.executable))].sort();
    expect(executables).toEqual(["aircrack-ng", "hcxpcapngtool", "kismet", "tshark"]);
    // §49: the 25-frame deauth burst is ONE event; a lone frame never
    // claims an attack.
    expect(store.wirelessSecurityEvents.some((e) => e.type === "DEAUTH_ACTIVITY")).toBe(true);
    // §67: authentication material in the capture is a COUNT only.
    expect(store.wirelessData.authenticationMaterialCount).toBeGreaterThan(0);
    const persisted = JSON.stringify({ findings: store.findings, wireless: store.wirelessData, events: store.events });
    expect(persisted).not.toContain("WPA*01*");
    expect(persisted).not.toContain(FAKE_WIFI_PSK);
  });

  it("detects a WPA3 → WPA2 security-mode downgrade as drift (§56/§88)", async () => {
    const { store, dag } = await makeWorld("WIRELESS_PASSIVE_BASELINE", {
      wirelessFixtures: {
        environmentId: "wl-env-1", environmentRef: FIXTURE_CORP_SSID, environmentKind: "CORPORATE",
        sensorRef: "sensor-1", sensorInterface: "wlan1",
        captureId: "capture-1", captureReference: "fixture://capture-1",
        approvedProfiles: APPROVED_PROFILES,
        previousAccessPoints: [{
          bssid: FIXTURE_AP_WPA2, ssid: FIXTURE_CORP_SSID, ssidHidden: false, channel: 6,
          securityMode: "WPA3", authentication: "SAE", pmf: "REQUIRED", wpsAdvertised: false,
          firstSeen: "2026-10-01T00:00:00.000Z", lastSeen: "2026-10-01T01:00:00.000Z", source: "kismet",
        }],
      },
    });
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.wirelessDriftRecords.some((d) => d.kind === "ENCRYPTION_CHANGED" && d.securityDowngrade === true)).toBe(true);
    expect(store.findings.some((f) => f.ruleId === "WIRELESS_SECURITY_MODE_DOWNGRADE" || f.title.includes("downgrade"))).toBe(true);
  });
});
