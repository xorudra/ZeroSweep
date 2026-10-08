import type { CarryForwardFindingRef } from "./types";
import type { TrafficRecordInput } from "./traffic";

/**
 * Prompt 35 fixtures — controlled, synthetic test data only (§140–
 * §161). The "insecure app" is a fixture description; the bearer
 * token is a SYNTHETIC value planted to prove §91/§154 redaction —
 * it must appear NOWHERE in any persisted output.
 */

export const FIXTURE_SYNTHETIC_BEARER = "Bearer FIXTURE_SYNTHETIC_TOKEN_DO_NOT_PERSIST";

export const FIXTURE_DEVICE_UNAPPROVED = {
  id: "device-fixture-1", deviceType: "ANDROID_TEST_DEVICE",
  authorizationStatus: "NOT_AUTHORIZED", availability: "AVAILABLE",
};
export const FIXTURE_DEVICE_APPROVED = {
  id: "device-fixture-2", deviceType: "ANDROID_EMULATOR",
  authorizationStatus: "AUTHORIZED", availability: "AVAILABLE",
};

export const FIXTURE_FRIDA_APPROVED_SCRIPT = {
  id: "frida-crypto-observe", version: "1.2.0",
  purpose: "CRYPTO_API_OBSERVATION", platform: "ANDROID",
  riskClass: "LOW", hash: "a".repeat(64), reviewStatus: "APPROVED",
};
export const FIXTURE_FRIDA_UNREVIEWED_SCRIPT = {
  id: "frida-unknown", version: "0.0.1",
  purpose: "RUNTIME_METHOD_OBSERVATION", platform: "ANDROID",
  riskClass: "MEDIUM", hash: "b".repeat(64), reviewStatus: "REGISTERED",
};

export const FIXTURE_TRAFFIC_AUTHORIZED: TrafficRecordInput = {
  method: "GET",
  url: "https://api.example.com/v1/profile",
  requestHeaders: [
    { name: "Authorization", value: FIXTURE_SYNTHETIC_BEARER },
    { name: "Cookie", value: "session=FIXTURE_SESSION" },
    { name: "Accept", value: "application/json" },
  ],
  sourceApp: "com.example.testapp",
  sourceDeviceId: "device-fixture-2",
  tls: { version: "TLSv1.3", certificateValid: true },
};

export const FIXTURE_TRAFFIC_CLEARTEXT: TrafficRecordInput = {
  method: "POST",
  url: "http://api.example.com/v1/login",
  requestHeaders: [{ name: "Content-Type", value: "application/json" }],
  sourceApp: "com.example.testapp",
  sourceDeviceId: "device-fixture-2",
  tls: { cleartext: true },
};

export const FIXTURE_FINDINGS_V1: CarryForwardFindingRef[] = [
  { crossBuildFingerprint: "mb:fp:cleartext", findingId: "f-v1-1", ruleId: "MOBILE_CLEARTEXT_TRAFFIC", title: "Cleartext traffic allowed", severity: "HIGH", status: "OPEN" },
  { crossBuildFingerprint: "mb:fp:secret", findingId: "f-v1-2", ruleId: "MOBILE_HARDCODED_SECRET", title: "Hardcoded API key", severity: "CRITICAL", status: "OPEN" },
  { crossBuildFingerprint: "mb:fp:exported", findingId: "f-v1-3", ruleId: "MOBILE_EXPORTED_COMPONENT", title: "Exported activity without permission", severity: "MEDIUM", status: "OPEN" },
];

export const FIXTURE_FINDINGS_V2: CarryForwardFindingRef[] = [
  // cleartext persists; secret is gone (FIXED_CANDIDATE); webview is new
  { crossBuildFingerprint: "mb:fp:cleartext", findingId: "f-v2-1", ruleId: "MOBILE_CLEARTEXT_TRAFFIC", title: "Cleartext traffic allowed", severity: "HIGH", status: "OPEN" },
  { crossBuildFingerprint: "mb:fp:webview", findingId: "f-v2-4", ruleId: "MOBILE_WEBVIEW_JS_ENABLED", title: "WebView JavaScript with file access", severity: "MEDIUM", status: "OPEN" },
];

export const FIXTURE_FINDINGS_V3: CarryForwardFindingRef[] = [
  // secret returns in V3 after being absent in V2 → REGRESSED
  { crossBuildFingerprint: "mb:fp:cleartext", findingId: "f-v3-1", ruleId: "MOBILE_CLEARTEXT_TRAFFIC", title: "Cleartext traffic allowed", severity: "HIGH", status: "OPEN" },
  { crossBuildFingerprint: "mb:fp:secret", findingId: "f-v3-2", ruleId: "MOBILE_HARDCODED_SECRET", title: "Hardcoded API key", severity: "CRITICAL", status: "OPEN" },
];
