/**
 * Prompt 19 — wireless security assessment types (§1–§99).
 *
 * The disciplines this module encodes end to end:
 *  - PASSIVE-FIRST (§IMPORTANT/§99): normal wireless scans NEVER
 *    disconnect users, transmit deauthentication frames, crack
 *    credentials, attempt WPA/WPA2 key recovery, capture credentials
 *    for reuse, create rogue access points, run evil-twin attacks,
 *    impersonate production SSIDs or jam channels. Those behaviours
 *    DO NOT EXIST in this codebase — they are named only so policy
 *    can refuse them explicitly and auditably (§99).
 *  - Identity is the BSSID (§5): an SSID is a label any AP can claim;
 *    it is never a unique identity and never a fingerprint on its own
 *    (§53). Authorization is never inferred from detectability (§4):
 *    an observed AP is data, not a target, and never expands scope.
 *  - Observed wireless data is UNTRUSTED INPUT (§91/§92): SSIDs and
 *    capture metadata are attacker-controlled strings — sanitized
 *    before persistence or display (control/ANSI/HTML stripping,
 *    length caps, invalid-Unicode replacement).
 *  - Station privacy (§8/§9): ordinary flows carry HMAC-pseudonymized
 *    station fingerprints only; raw addresses require the elevated
 *    VIEW_RAW_WIRELESS_CAPTURES permission and are audited (§30/§96).
 *  - Authentication material in captures is METADATA ONLY (§67): a
 *    count may be recorded; the material itself never persists.
 *  - Sensor reality (§12–§14): live RF collection runs ONLY on
 *    dedicated approved sensors of type WIRELESS_PASSIVE_ANALYSIS.
 *    General workers run OFFLINE capture analysis; sensor-dependent
 *    stages report NOT_CONFIGURED/PARTIAL honestly rather than
 *    fabricating observations.
 */
import type {
  NormalizedWirelessData, WirelessFindingType, WirelessPmfState, WirelessSecurityMode,
} from "../findings/finding.types";

export type {
  NormalizedWirelessAccessPoint, NormalizedWirelessChannelObservation,
  NormalizedWirelessData, NormalizedWirelessObservation, NormalizedWirelessSecurityEvent,
  NormalizedWirelessStation, WirelessFindingType, WirelessPmfState, WirelessSecurityMode,
} from "../findings/finding.types";

/** §13: the two wireless worker capabilities stay SEPARATE — passive
 *  analysis is the baseline; lab validation is a governed, explicitly
 *  authorized workflow on dedicated lab sensors only. */
export const WIRELESS_WORKER_CAPABILITIES = {
  PASSIVE: "WIRELESS_PASSIVE_ANALYSIS",
  LAB: "WIRELESS_LAB_VALIDATION",
} as const;

/** §61: ScanBudget extensions for wireless work. */
export interface WirelessScanBudget {
  maxSensors: number;
  maxChannels: number;
  maxCaptureDurationSeconds: number;
  maxCaptureBytes: number;
  maxObservedAPs: number;
  maxObservedStations: number;
  maxFramesProcessed: number;
  maxArtifactSizeBytes: number;
  maxAnalysisDurationSeconds: number;
}

export const DEFAULT_WIRELESS_BUDGET: WirelessScanBudget = {
  maxSensors: 4,
  maxChannels: 64,
  maxCaptureDurationSeconds: 3600,
  maxCaptureBytes: 512 * 1024 * 1024,
  maxObservedAPs: 5000,
  maxObservedStations: 20000,
  maxFramesProcessed: 5_000_000,
  maxArtifactSizeBytes: 512 * 1024 * 1024,
  maxAnalysisDurationSeconds: 1800,
};

/** §99/§19/§67: PROHIBITED AUTOMATION. Never implemented, never
 *  plannable, never executable — the names exist so the policy can
 *  refuse them explicitly and auditably. */
export const PROHIBITED_WIRELESS_AUTOMATION = [
  "WIFI_PASSWORD_CRACKING",
  "WPA_KEY_RECOVERY",
  "WPS_PIN_ATTACK",
  "DEAUTHENTICATION_ATTACK",
  "DISASSOCIATION_ATTACK",
  "EVIL_TWIN_CREATION",
  "ROGUE_AP_CREATION",
  "CREDENTIAL_INTERCEPTION",
  "CREDENTIAL_REUSE",
  "RF_JAMMING",
  "WIRELESS_PERSISTENCE",
  "THIRD_PARTY_NETWORK_ATTACK",
  "ARBITRARY_AIRCRACK_ARGUMENTS",
  "ARBITRARY_TSHARK_FILTER",
  "WIFITE_AUTOMATION",
  "HCXDUMPTOOL_ACTIVE_CAPTURE",
] as const;
export type ProhibitedWirelessAction = (typeof PROHIBITED_WIRELESS_AUTOMATION)[number];

export function isProhibitedWirelessAction(value: string): boolean {
  return (PROHIBITED_WIRELESS_AUTOMATION as readonly string[]).includes(value.toUpperCase());
}

/** §21/§22/§25/§64: tool registrations that NEVER execute in baseline
 *  orchestration. Wifite is ACTIVE_WIRELESS_TESTING (INTRUSIVE) and
 *  hcxdumptool is ACTIVE_WIRELESS_CAPTURE — both DISABLED outside an
 *  explicitly controlled lab workflow (§65), and no lab adapter
 *  exists in this build. Wireshark is an ANALYST_TOOL (§25): backend
 *  automation uses tshark; no GUI dependency is invented. */
export interface WirelessDisabledRegistration {
  slug: string;
  name: string;
  capabilities: string[];
  executionState: "DISABLED" | "ANALYST_TOOL";
  classification: string;
  reason: string;
}

export const WIRELESS_DISABLED_REGISTRATIONS: WirelessDisabledRegistration[] = [
  {
    slug: "wifite",
    name: "Wifite",
    capabilities: ["ACTIVE_WIRELESS_TESTING"],
    executionState: "DISABLED",
    classification: "ACTIVE_WIRELESS_TESTING",
    reason: "Prompt 19 §21/§64: Wifite is ACTIVE_WIRELESS_TESTING, risk INTRUSIVE, default DISABLED. ToolSelector must never choose it for WIRELESS_PASSIVE_BASELINE or WIRELESS_PASSIVE_COMPREHENSIVE, and no executing adapter exists — its workflows (deauthentication, handshake capture, cracking orchestration) are prohibited automation in this platform (§99).",
  },
  {
    slug: "hcxdumptool",
    name: "hcxdumptool",
    capabilities: ["ACTIVE_WIRELESS_CAPTURE"],
    executionState: "DISABLED",
    classification: "ACTIVE_WIRELESS_CAPTURE",
    reason: "Prompt 19 §22/§64: hcxdumptool is ACTIVE_WIRELESS_CAPTURE and DISABLED outside explicitly controlled lab workflows. It is never used automatically against surrounding networks and no executing adapter exists in this build.",
  },
  {
    slug: "wireshark",
    name: "Wireshark",
    capabilities: ["PCAP_ANALYSIS", "FRAME_ANALYSIS_80211"],
    executionState: "ANALYST_TOOL",
    classification: "ANALYST_TOOL",
    reason: "Prompt 19 §25: Wireshark is analyst-facing tooling. Backend automation uses tshark (TsharkWirelessAdapter) — DSRclone does not invent a headless Wireshark dependency.",
  },
];

/** §80: the wireless tool-health surface — every tool the spec names,
 *  with worker type, risk, active/passive classification and approval
 *  requirement. */
export interface WirelessToolDescriptor {
  slug: string;
  name: string;
  kind: "ADAPTER" | "CONNECTOR" | "DISABLED" | "ANALYST_TOOL";
  workerType: string;
  riskLevel: "PASSIVE" | "LOW" | "MODERATE" | "INTRUSIVE" | "RESTRICTED";
  classification: "PASSIVE" | "OFFLINE" | "ACTIVE";
  requiresApproval: boolean;
  capabilities: string[];
  note: string;
}

export const WIRELESS_TOOL_DESCRIPTORS: WirelessToolDescriptor[] = [
  {
    slug: "kismet", name: "Kismet", kind: "ADAPTER", workerType: "WIRELESS_PASSIVE_ANALYSIS",
    riskLevel: "PASSIVE", classification: "PASSIVE", requiresApproval: true,
    capabilities: ["PASSIVE_WIFI_DISCOVERY", "ACCESS_POINT_INVENTORY", "STATION_OBSERVATION", "CHANNEL_OBSERVATION", "WIRELESS_SECURITY_METADATA"],
    note: "Passive collection profiles only (§16): Kismet listens — it never transmits, associates or probes.",
  },
  {
    slug: "aircrack-ng", name: "Aircrack-ng (metadata only)", kind: "ADAPTER", workerType: "WIRELESS_PASSIVE_ANALYSIS",
    riskLevel: "MODERATE", classification: "OFFLINE", requiresApproval: true,
    capabilities: ["CAPTURE_METADATA_ANALYSIS", "WIRELESS_CONFIGURATION_ANALYSIS", "OFFLINE_CAPTURE_INSPECTION"],
    note: "Restricted by AircrackPolicy (§19/§20): capture inspection + metadata extraction ONLY. Cracking, key recovery and deauthentication modes are not expressible in any plan.",
  },
  {
    slug: "hcxtools", name: "hcxtools (hcxpcapngtool)", kind: "ADAPTER", workerType: "WIRELESS_PASSIVE_ANALYSIS",
    riskLevel: "LOW", classification: "OFFLINE", requiresApproval: true,
    capabilities: ["OFFLINE_CAPTURE_PROCESSING", "CAPTURE_METADATA_EXTRACTION"],
    note: "Offline processing of APPROVED capture artifacts only (§23). Hash-export modes are not expressible; authentication material is counted, never extracted (§67).",
  },
  {
    slug: "tshark-wireless", name: "tshark (wireless)", kind: "ADAPTER", workerType: "WIRELESS_PASSIVE_ANALYSIS",
    riskLevel: "PASSIVE", classification: "OFFLINE", requiresApproval: false,
    capabilities: ["PCAP_ANALYSIS", "FRAME_ANALYSIS_80211", "WIRELESS_PROTOCOL_METADATA"],
    note: "Offline 802.11 frame analysis over uploaded captures (§24) with a FIXED platform field set — arbitrary display filters are not expressible (§78).",
  },
  {
    slug: "wifite", name: "Wifite", kind: "DISABLED", workerType: "WIRELESS_LAB_VALIDATION",
    riskLevel: "INTRUSIVE", classification: "ACTIVE", requiresApproval: true,
    capabilities: ["ACTIVE_WIRELESS_TESTING"],
    note: "DISABLED (§21/§64): never invoked by baseline scans; no adapter exists.",
  },
  {
    slug: "hcxdumptool", name: "hcxdumptool", kind: "DISABLED", workerType: "WIRELESS_LAB_VALIDATION",
    riskLevel: "MODERATE", classification: "ACTIVE", requiresApproval: true,
    capabilities: ["ACTIVE_WIRELESS_CAPTURE"],
    note: "DISABLED outside explicitly controlled lab workflows (§22/§64); never used against surrounding networks.",
  },
  {
    slug: "wireshark", name: "Wireshark", kind: "ANALYST_TOOL", workerType: "WIRELESS_PASSIVE_ANALYSIS",
    riskLevel: "PASSIVE", classification: "OFFLINE", requiresApproval: false,
    capabilities: ["PCAP_ANALYSIS", "FRAME_ANALYSIS_80211"],
    note: "Analyst-facing GUI tooling (§25); backend automation uses tshark.",
  },
];

/** §43: an approved wireless profile — the expected posture the
 *  rogue-AP analysis (§42) diffs observations against. */
export interface ApprovedWirelessProfileShape {
  ssid: string;
  bssid?: string;
  securityMode: WirelessSecurityMode;
  authentication?: string;
  allowedChannels: number[];
  allowedBands: string[];
  environmentRef?: string;
}

/** §44: rogue classification — an unknown AP is UNKNOWN, never
 *  "malicious" without evidence. */
export type RogueClassification = "APPROVED" | "UNKNOWN" | "SUSPICIOUS" | "POLICY_VIOLATION";

/** §56: wireless drift kinds — drift is a configuration fact, not an
 *  accusation; it is never labelled malicious by itself. */
export type WirelessDriftKind =
  | "ENCRYPTION_CHANGED" | "AUTHENTICATION_CHANGED" | "NEW_AP"
  | "AP_DISAPPEARED" | "BSSID_CHANGED" | "CHANNEL_POLICY_CHANGED";

/** §60: the wireless security quality gate rules. */
export interface WirelessGateRules {
  noWep: boolean;
  noUnauthorizedOpenCorporateSsids: boolean;
  noCriticalRogueApFinding: boolean;
  requiredPmfEnvironments: string[]; // environment kinds (e.g. CORPORATE)
  prohibitedSecurityModes: WirelessSecurityMode[];
}

export const DEFAULT_WIRELESS_GATE_RULES: WirelessGateRules = {
  noWep: true,
  noUnauthorizedOpenCorporateSsids: true,
  noCriticalRogueApFinding: true,
  requiredPmfEnvironments: ["CORPORATE"],
  prohibitedSecurityModes: ["WEP"],
};

/** §58: organizational wireless compliance controls — policy mappings
 *  only; the platform never claims formal certification. */
export const WIRELESS_COMPLIANCE_CONTROLS = [
  { controlId: "WIFI-ENC-01", name: "Approved encryption required", description: "Corporate SSIDs must use WPA2/WPA3 or Enterprise authentication; WEP and WPA/TKIP are prohibited." },
  { controlId: "WIFI-LEG-02", name: "Legacy protocols prohibited", description: "WEP, WPA (v1) and TKIP must not be observed on approved infrastructure." },
  { controlId: "WIFI-INV-03", name: "Approved AP inventory", description: "Every corporate-SSID AP must match an ApprovedWirelessProfile or be classified and reviewed." },
  { controlId: "WIFI-PMF-04", name: "Management-frame protection policy", description: "PMF must be REQUIRED on corporate environments where client support permits; NOT_OBSERVED is a posture finding." },
] as const;

/** Parsed envelope shared by wireless parsers/adapters (mirrors the
 *  binary family's ParsedBinary shape). */
export interface ParsedWireless {
  findings: import("../findings/finding.types").NormalizedFinding[];
  wireless?: NormalizedWirelessData;
  metrics: Record<string, number>;
}

export function emptyParsedWireless(metrics: Record<string, number> = {}): ParsedWireless {
  return { findings: [], metrics };
}

/** §17: Kismet instance connector deps — an administrator-managed
 *  Kismet sensor/server. Authentication is a SECRET REFERENCE only;
 *  no credential value is ever expressible here. The production
 *  transport is deliberately unwired in this build: instances report
 *  NOT_CONFIGURED honestly rather than fabricating observations. */
export interface KismetInstanceDeps {
  instanceConfigured: boolean;
  instanceRef?: string;
}

export const INERT_KISMET_DEPS: KismetInstanceDeps = { instanceConfigured: false };
