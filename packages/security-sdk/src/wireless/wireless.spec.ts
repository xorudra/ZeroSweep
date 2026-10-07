/**
 * Prompt 19 — controlled wireless tests (§81–§95, SDK level).
 *
 * Everything runs over synthetic fixtures: documentation SSIDs,
 * fixture OUIs, a synthetic pcap header. No radio exists here, no
 * tool transmits, and the planted FAKE_WIFI_PSK must exist in NO
 * parsed output (§67).
 */
import { describe, expect, it } from "vitest";
import {
  analyzeWirelessPosture, detectWirelessDrift, evaluateWirelessGate,
  wirelessFindingFingerprint,
} from "./analysis";
import { validateWirelessCaptureUpload, captureHeaderSanity, detectCaptureFormat } from "./intake";
import {
  mergeWirelessData, parseAircrackCaptureInfo, parseHcxPcapngToolSummary,
  parseKismetDevices, parseTsharkWirelessFields,
} from "./parsers-wireless";
import {
  evaluateActiveToolRequest, evaluateAircrackConfig, evaluateWirelessAction, evaluateWirelessLabPolicy,
} from "./policy";
import { planWirelessRetest } from "./retest";
import {
  maskMacAddress, normalizeBssid, pseudonymizeStationAddress, sanitizeSsid,
} from "./sanitize";
import { normalizeWirelessSecurity } from "./security";
import {
  AIRCRACK_INFO_FIXTURE, FAKE_WIFI_PSK, FIXTURE_AP_GUEST_OPEN, FIXTURE_AP_ROGUE, FIXTURE_AP_WEP,
  FIXTURE_AP_WPA2, FIXTURE_AP_WPA3, FIXTURE_CORP_SSID, FIXTURE_MALFORMED_PCAP_BYTES, FIXTURE_PCAP_BYTES,
  FIXTURE_PCAP_SHA256, FIXTURE_PCAPNG_BYTES, FIXTURE_STATION_MAC, HCX_SUMMARY_FIXTURE,
  KISMET_DRIFT_FIXTURE_JSON, KISMET_FIXTURE_JSON, KISMET_FIXTURE_JSON_SENSOR2, TSHARK_WIRELESS_FIXTURE,
} from "./fixtures";
import { assertWirelessConfig } from "./wireless-adapter.base";
import type { WirelessAnalysisContext } from "./analysis";

const CTX = { toolSlug: "kismet", sensorRef: "sensor-1", workspaceKey: "ws-1-key" };
const ANALYSIS_CTX: WirelessAnalysisContext = {
  environmentId: "env-1", environmentKind: "CORPORATE",
  approvedProfiles: [
    { ssid: FIXTURE_CORP_SSID, bssid: FIXTURE_AP_WPA2, securityMode: "WPA2", authentication: "PSK", allowedChannels: [6], allowedBands: ["2.4GHZ"] },
    { ssid: FIXTURE_CORP_SSID, bssid: FIXTURE_AP_WPA3, securityMode: "WPA3", authentication: "SAE", allowedChannels: [36], allowedBands: ["5GHZ"] },
    { ssid: "example-guest-wifi", bssid: FIXTURE_AP_GUEST_OPEN, securityMode: "OPEN", allowedChannels: [1], allowedBands: ["2.4GHZ"] },
  ],
};

describe("§82 Kismet parser — normalization + dedup", () => {
  const parsed = parseKismetDevices(KISMET_FIXTURE_JSON, CTX);
  const data = parsed.wireless!;

  it("normalizes AP identity, SSID, channel, security, signal", () => {
    const wpa2 = data.accessPoints.find((a) => a.bssid === FIXTURE_AP_WPA2)!;
    expect(wpa2.ssid).toBe(FIXTURE_CORP_SSID);
    expect(wpa2.channel).toBe(6);
    expect(wpa2.band).toBe("2.4GHZ");
    expect(wpa2.frequencyMhz).toBe(2437);
    expect(wpa2.securityMode).toBe("WPA2");
    expect(wpa2.authentication).toBe("PSK");
    expect(wpa2.encryption).toBe("CCMP");
    expect(wpa2.signalDbm).toBe(-42);
    const wpa3 = data.accessPoints.find((a) => a.bssid === FIXTURE_AP_WPA3)!;
    expect(wpa3.securityMode).toBe("WPA3");
    expect(wpa3.band).toBe("5GHZ");
    const wep = data.accessPoints.find((a) => a.bssid === FIXTURE_AP_WEP)!;
    expect(wep.securityMode).toBe("WEP");
    const hidden = data.accessPoints.find((a) => a.ssidHidden)!;
    expect(hidden.ssid).toBe("");
  });

  it("pseudonymizes stations — the raw MAC never appears (§9)", () => {
    expect(data.stations).toHaveLength(1);
    expect(data.stations[0]!.addressFingerprint).toBe(pseudonymizeStationAddress(FIXTURE_STATION_MAC, "ws-1-key"));
    expect(JSON.stringify(data)).not.toContain(FIXTURE_STATION_MAC);
    expect(data.stations[0]!.associatedBssid).toBe(FIXTURE_AP_WPA2);
  });

  it("§67: the planted PSK exists in NO parsed output", () => {
    expect(JSON.stringify(parsed)).not.toContain(FAKE_WIFI_PSK);
    expect(JSON.stringify(parsed)).not.toContain("FAKE_WIFI_PSK");
  });

  it("§54/§86: two sensors observing the same BSSID merge to ONE AP", () => {
    const s2 = parseKismetDevices(KISMET_FIXTURE_JSON_SENSOR2, { ...CTX, sensorRef: "sensor-2" }).wireless!;
    const merged = mergeWirelessData([data, s2]);
    expect(merged.accessPoints.filter((a) => a.bssid === FIXTURE_AP_WPA2)).toHaveLength(1);
    expect(merged.observations.filter((o) => o.bssid === FIXTURE_AP_WPA2)).toHaveLength(2);
  });
});

describe("§92 hostile SSID", () => {
  it("terminal escapes are stripped and length is capped at parse time", () => {
    const parsed = parseKismetDevices(KISMET_FIXTURE_JSON, CTX);
    const hostile = parsed.wireless!.accessPoints.find((a) => a.bssid === "00:0b:86:66:77:88")!;
    expect(hostile.ssid).not.toContain("\u001b");
    expect(hostile.ssid).not.toContain("[31m");
    expect(hostile.ssid.length).toBeLessThanOrEqual(64);
    const long = sanitizeSsid("A".repeat(500));
    expect(long.ssid.length).toBeLessThanOrEqual(64);
  });
  it("BSSID normalization accepts common forms and rejects garbage (§5)", () => {
    expect(normalizeBssid("AA-BB-CC-DD-EE-FF")).toBe("aa:bb:cc:dd:ee:ff");
    expect(normalizeBssid("aabb.ccdd.eeff")).toBe("aa:bb:cc:dd:ee:ff");
    expect(normalizeBssid("not-a-mac")).toBeUndefined();
    expect(maskMacAddress(FIXTURE_AP_WPA2)).toBe("00:0b:86:**:**:**");
  });
});

describe("§83/§84/§85 capture intake", () => {
  it("proves format from magic bytes, never the extension", () => {
    expect(detectCaptureFormat(FIXTURE_PCAP_BYTES)).toBe("PCAP");
    expect(detectCaptureFormat(FIXTURE_PCAPNG_BYTES)).toBe("PCAPNG");
    const ok = validateWirelessCaptureUpload({ name: "survey.txt", sizeBytes: FIXTURE_PCAP_BYTES.length, content: FIXTURE_PCAP_BYTES, declaredSha256: FIXTURE_PCAP_SHA256 });
    expect(ok.accepted).toBe(true);
    expect(ok.format).toBe("PCAP");
    expect(ok.sha256).toBe(FIXTURE_PCAP_SHA256);
  });
  it("malformed/truncated captures fail safely (§84)", () => {
    const bad = validateWirelessCaptureUpload({ name: "bad.pcap", sizeBytes: FIXTURE_MALFORMED_PCAP_BYTES.length, content: FIXTURE_MALFORMED_PCAP_BYTES });
    expect(bad.accepted).toBe(true); // magic proves pcap; header sanity is the worker's gate
    expect(captureHeaderSanity(FIXTURE_MALFORMED_PCAP_BYTES).ok).toBe(false);
    const junk = validateWirelessCaptureUpload({ name: "x.pcap", sizeBytes: 8, content: Buffer.from("notacap!") });
    expect(junk.accepted).toBe(false);
    expect(junk.reasonCode).toBe("CAPTURE_FORMAT_UNPROVEN");
  });
  it("huge captures are rejected before parsing (§85)", () => {
    const huge = validateWirelessCaptureUpload({ name: "huge.pcap", sizeBytes: 600 * 1024 * 1024, magicPrefix: FIXTURE_PCAP_BYTES });
    expect(huge.accepted).toBe(false);
    expect(huge.reasonCode).toBe("CAPTURE_EXCEEDS_BUDGET");
  });
});

describe("§24/§89 tshark parser + deauth detection", () => {
  const parsed = parseTsharkWirelessFields(TSHARK_WIRELESS_FIXTURE, { ...CTX, toolSlug: "tshark-wireless" });
  it("builds AP inventory from beacons incl. OPEN vs WEP via the privacy bit", () => {
    const aps = parsed.wireless!.accessPoints;
    expect(aps.find((a) => a.bssid === FIXTURE_AP_WPA2)?.securityMode).toBe("WPA2");
    expect(aps.find((a) => a.bssid === FIXTURE_AP_GUEST_OPEN)?.securityMode).toBe("OPEN");
    expect(aps.find((a) => a.bssid === FIXTURE_AP_WEP)?.securityMode).toBe("WEP");
    expect(parsed.wireless!.framesProcessed).toBe(29);
  });
  it("a deauth BURST becomes a passive event — no frames transmitted (§47/§89)", () => {
    const events = parsed.wireless!.securityEvents;
    expect(events).toHaveLength(1);
    expect(events[0]!.type).toBe("DEAUTH_ACTIVITY");
    expect(events[0]!.confidence).toBe("MEDIUM");
  });
  it("a single deauth frame never claims an attack (§49)", () => {
    const one = parseTsharkWirelessFields(
      `1760000100\t${FIXTURE_AP_WPA2}\t\t6\t2437\t-40\t0x0c\t${FIXTURE_AP_WPA2}\tff:ff:ff:ff:ff:ff\t\t\t\t1`,
      { ...CTX, toolSlug: "tshark-wireless" },
    );
    expect(one.wireless!.securityEvents).toHaveLength(0);
  });
});

describe("§19/§23 offline tool parsers", () => {
  it("aircrack inspection parses the network table + counts handshakes as metadata", () => {
    const parsed = parseAircrackCaptureInfo(AIRCRACK_INFO_FIXTURE, { ...CTX, toolSlug: "aircrack-ng" });
    expect(parsed.wireless!.accessPoints.find((a) => a.bssid === FIXTURE_AP_WPA2)?.securityMode).toBe("WPA2");
    expect(parsed.wireless!.authenticationMaterialCount).toBe(1);
  });
  it("hcxtools summary counts hash material and never retains it (§67)", () => {
    const parsed = parseHcxPcapngToolSummary(HCX_SUMMARY_FIXTURE, { ...CTX, toolSlug: "hcxtools" });
    expect(parsed.wireless!.authenticationMaterialCount).toBe(1);
    expect(JSON.stringify(parsed)).not.toContain("WPA*01");
    expect(parsed.wireless!.accessPoints.map((a) => a.bssid)).toContain(FIXTURE_AP_WPA2);
  });
  it("malformed tool output fails closed", () => {
    expect(parseHcxPcapngToolSummary("", CTX).metrics.parserFailures).toBe(1);
    expect(parseKismetDevices("not json", CTX).metrics.parserFailures).toBe(1);
  });
});

describe("§87 rogue AP + §42–§45 classification", () => {
  const data = parseKismetDevices(KISMET_FIXTURE_JSON, CTX).wireless!;
  const posture = analyzeWirelessPosture(data, ANALYSIS_CTX);
  it("same SSID + unexpected BSSID + weaker security = SUSPICIOUS, never 'confirmed evil twin'", () => {
    const rogue = posture.classifications.find((c) => c.bssid === FIXTURE_AP_ROGUE)!;
    expect(rogue.classification).toBe("SUSPICIOUS");
    const f = posture.findings.find((x) => x.wirelessBssid === FIXTURE_AP_ROGUE && x.wirelessFindingType === "WIRELESS_ROGUE_AP_FINDING")!;
    expect(f).toBeDefined();
    expect(f.wirelessFindingType).toBe("WIRELESS_ROGUE_AP_FINDING");
    expect(f.description).toContain("NOT a confirmed evil twin");
    expect(posture.events.some((e) => e.type === "ROGUE_AP_SUSPECTED")).toBe(true);
  });
  it("approved APs classify APPROVED; §44 unknown APs are UNKNOWN, not malicious", () => {
    expect(posture.classifications.find((c) => c.bssid === FIXTURE_AP_WPA2)?.classification).toBe("APPROVED");
    const hostile = posture.classifications.find((c) => c.bssid === "00:0b:86:66:77:88")!;
    expect(hostile.classification).toBe("UNKNOWN");
  });
  it("§53 fingerprint never depends on SSID alone", () => {
    const a = wirelessFindingFingerprint({ environmentId: "e", bssid: FIXTURE_AP_WPA2, rule: "R", securityMode: "WPA2", findingClass: "C" });
    const b = wirelessFindingFingerprint({ environmentId: "e", bssid: FIXTURE_AP_WPA3, rule: "R", securityMode: "WPA2", findingClass: "C" });
    expect(a).not.toBe(b);
  });
});

describe("§33/§34/§60 posture findings + gate", () => {
  const data = parseKismetDevices(KISMET_FIXTURE_JSON, CTX).wireless!;
  const posture = analyzeWirelessPosture(data, ANALYSIS_CTX);
  it("WEP is a HIGH encryption finding; open guest is contextual LOW", () => {
    const wep = posture.findings.find((f) => f.wirelessBssid === FIXTURE_AP_WEP)!;
    expect(wep.severity).toBe("HIGH");
    expect(wep.wirelessFindingType).toBe("WIRELESS_ENCRYPTION_FINDING");
    const guestProfile = { ...ANALYSIS_CTX, environmentKind: "GUEST" };
    const guestPosture = analyzeWirelessPosture(data, guestProfile);
    const open = guestPosture.findings.find((f) => f.wirelessBssid === FIXTURE_AP_GUEST_OPEN && f.title.includes("Open"))!;
    expect(open.severity).toBe("LOW");
  });
  it("gate fails on WEP (§60)", () => {
    expect(posture.gate.status).toBe("FAILED");
    expect(posture.gate.failedRules).toContain("NO_WEP");
    const clean = evaluateWirelessGate(
      [{ ...data.accessPoints.find((a) => a.bssid === FIXTURE_AP_WPA3)! }], [], ANALYSIS_CTX,
    );
    expect(clean.status).toBe("PASSED");
  });
});

describe("§88 drift — WPA3 → OPEN", () => {
  it("produces drift + a SECURITY_MODE_CHANGED event + a downgrade finding", () => {
    const before = parseKismetDevices(KISMET_FIXTURE_JSON, CTX).wireless!.accessPoints;
    const after = parseKismetDevices(KISMET_DRIFT_FIXTURE_JSON, CTX).wireless!.accessPoints;
    const { drift, findings, events } = detectWirelessDrift(before, after, ANALYSIS_CTX);
    const enc = drift.find((d) => d.kind === "ENCRYPTION_CHANGED" && d.bssid === FIXTURE_AP_WPA3)!;
    expect(enc.fromValue).toBe("WPA3");
    expect(enc.toValue).toBe("OPEN");
    expect(enc.securityDowngrade).toBe(true);
    expect(events.some((e) => e.type === "SECURITY_MODE_CHANGED")).toBe(true);
    expect(findings.some((f) => f.title.includes("downgrade"))).toBe(true);
  });
});

describe("§59 retest", () => {
  it("WPA2 PMF issue resolves on fresh observation; unobserved AP is INCONCLUSIVE", () => {
    const before = analyzeWirelessPosture(parseKismetDevices(KISMET_FIXTURE_JSON, CTX).wireless!, ANALYSIS_CTX);
    const pmf = before.findings.find((f) => f.title.includes("Protected Management Frames") && f.wirelessBssid === FIXTURE_AP_WPA2)!;
    expect(pmf).toBeDefined();
    const fixed = parseKismetDevices(KISMET_FIXTURE_JSON, CTX).wireless!.accessPoints
      .map((a) => (a.bssid === FIXTURE_AP_WPA2 ? { ...a, pmf: "REQUIRED" as const } : a));
    const verdicts = planWirelessRetest(
      [{ fingerprint: pmf.wirelessFingerprint!, rule: "WIRELESS_PMF_NOT_REQUIRED", bssid: FIXTURE_AP_WPA2, securityMode: "WPA2" },
       { fingerprint: "x", rule: "WIRELESS_WEP_IN_USE", bssid: "00:0b:86:00:00:99", securityMode: "WEP" }],
      fixed, ANALYSIS_CTX,
    );
    expect(verdicts[0]!.verdict).toBe("RESOLVED");
    expect(verdicts[1]!.verdict).toBe("INCONCLUSIVE");
  });
});

describe("§20/§64/§91/§93 policy", () => {
  it("AircrackPolicy refuses cracking-shaped config (§20)", () => {
    expect(evaluateAircrackConfig({ wordlist: "/usr/share/words" }).allowed).toBe(false);
    expect(evaluateAircrackConfig({ wirelessCaptureRef: "cap-1" }).allowed).toBe(true);
  });
  it("command/filter/credential keys are not expressible (§78/§91)", () => {
    expect(() => assertWirelessConfig({ filter: "wlan.fc == 1" })).toThrow(/not expressible/);
    expect(() => assertWirelessConfig({ psk: "hunter2" })).toThrow(/secret references/);
    expect(() => assertWirelessConfig({ wirelessCaptureRef: "cap-1" })).not.toThrow();
  });
  it("Wifite / active hcxdumptool are BLOCKED for baseline profiles (§93)", () => {
    expect(evaluateActiveToolRequest({ slug: "wifite", profile: "WIRELESS_PASSIVE_BASELINE" }).allowed).toBe(false);
    expect(evaluateActiveToolRequest({ slug: "hcxdumptool", profile: "WIRELESS_PASSIVE_COMPREHENSIVE" }).reasonCode).toBe("WIRELESS_ACTIVE_TOOL_BLOCKED");
    expect(evaluateActiveToolRequest({ slug: "kismet", profile: "WIRELESS_PASSIVE_BASELINE" }).allowed).toBe(true);
  });
  it("prohibited automation is refused by name (§99)", () => {
    expect(evaluateWirelessAction("WPA_KEY_RECOVERY").allowed).toBe(false);
    expect(evaluateWirelessAction("DEAUTHENTICATION_ATTACK").allowed).toBe(false);
    expect(evaluateWirelessAction("PASSIVE_WIFI_DISCOVERY").allowed).toBe(true);
  });
  it("lab policy: full requirements → ELIGIBLE_NOT_PROVISIONED; gaps → BLOCKED (§65)", () => {
    const ok = evaluateWirelessLabPolicy({
      environmentKind: "LAB", dedicatedTestAp: true, dedicatedTestClients: true,
      authorizationId: "auth-1", approved: true, requestedDurationSeconds: 600,
      killSwitchEngaged: false, syntheticCredentialsOnly: true,
    });
    expect(ok.status).toBe("ELIGIBLE_NOT_PROVISIONED");
    const bad = evaluateWirelessLabPolicy({
      environmentKind: "CORPORATE", dedicatedTestAp: false, dedicatedTestClients: false,
      approved: false, requestedDurationSeconds: 99999, killSwitchEngaged: true, syntheticCredentialsOnly: false,
    });
    expect(bad.status).toBe("BLOCKED");
  });
});

describe("§31/§35 security normalization is evidence-based", () => {
  it("WPA3 is never inferred from an SSID name — evidence only", () => {
    const none = normalizeWirelessSecurity({});
    expect(none.mode).toBe("UNKNOWN");
    const sae = normalizeWirelessSecurity({ versions: ["WPA2", "WPA3"], akms: ["PSK", "SAE"], ciphers: ["CCMP"] });
    expect(sae.mode).toBe("TRANSITION");
    const ent = normalizeWirelessSecurity({ versions: ["WPA2"], akms: ["EAP"], ciphers: ["CCMP"] });
    expect(ent.mode).toBe("ENTERPRISE");
    expect(ent.authentication).toBe("EAP/802.1X");
  });
});
