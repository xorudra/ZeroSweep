/**
 * Prompt 17 — mobile application security types (§4–§92).
 *
 * The disciplines this module encodes end to end:
 *  - STATIC analysis is the default and the norm (§8): uploaded app
 *    binaries are hostile content — hashed, validated, parsed — and
 *    NEVER installed, executed, emulated or instrumented outside the
 *    governed device lab (§53–§61).
 *  - Dynamic instrumentation (Frida/Objection) exists ONLY as governed
 *    descriptors + an approval policy (§69–§74): administrator-
 *    reviewed, versioned, hashed modules; no arbitrary user-supplied
 *    JavaScript, no generic ADB shell, no arbitrary Objection
 *    commands — anywhere (§75).
 *  - Secrets found inside apps persist as METADATA ONLY (§28): type,
 *    detector, location, one-way fingerprint, redacted preview. The
 *    raw value never appears in any record this module produces.
 *  - Extracted endpoints are DISCOVERED_REFERENCEs (§29): they feed
 *    the API asset model but NEVER authorize a target or expand scope.
 *  - Signing keys / store credentials never exist here (§31) —
 *    secret references only, validated by the shared cloudsec guards.
 */
import type { NormalizedMobileData } from "../findings/finding.types";

export type MobilePlatformName = "ANDROID" | "IOS";
export type MobileArtifactFormat = "APK" | "AAB" | "IPA" | "DEX" | "UNKNOWN";

/** §10: the two worker capabilities stay SEPARATE — static workers
 *  never run dynamic tooling and dynamic workers need the stronger
 *  lab isolation. */
export const MOBILE_WORKER_CAPABILITIES = {
  STATIC: "MOBILE_STATIC_ANALYSIS",
  DYNAMIC: "MOBILE_DYNAMIC_ANALYSIS",
} as const;

/** §91: ScanBudget extensions for mobile work. */
export interface MobileScanBudget {
  maxArtifactSizeMb: number;
  maxExtractedFiles: number;
  maxExtractedBytesMb: number;
  maxDecompilationSeconds: number;
  maxBinaryAnalysisSeconds: number;
  maxDynamicDurationSeconds: number;
  maxTrafficCaptureMb: number;
  maxProxyRequests: number;
  maxInstrumentationModules: number;
}

export const DEFAULT_MOBILE_BUDGET: MobileScanBudget = {
  maxArtifactSizeMb: 500,
  maxExtractedFiles: 20000,
  maxExtractedBytesMb: 2048,
  maxDecompilationSeconds: 1800,
  maxBinaryAnalysisSeconds: 1800,
  maxDynamicDurationSeconds: 3600,
  maxTrafficCaptureMb: 256,
  maxProxyRequests: 10000,
  maxInstrumentationModules: 8,
};

/** §75/§119: PROHIBITED AUTOMATION. These actions are never
 *  implemented, never plannable and never executable — the names
 *  exist so the policy can refuse them explicitly and auditably. */
export const PROHIBITED_MOBILE_AUTOMATION = [
  "CREDENTIAL_THEFT",
  "SESSION_TOKEN_THEFT",
  "ACCOUNT_TAKEOVER",
  "PAYMENT_MANIPULATION",
  "PAYMENT_ABUSE",
  "DEVICE_PERSISTENCE",
  "SPYWARE_BEHAVIOR",
  "SMS_INTERCEPTION",
  "CONTACT_EXTRACTION",
  "PERSONAL_FILE_EXTRACTION",
  "THIRD_PARTY_SECURITY_CONTROL_BYPASS",
  "ARBITRARY_ADB_SHELL",
  "ARBITRARY_FRIDA_SCRIPT",
  "ARBITRARY_OBJECTION_COMMAND",
  "PERSONAL_DEVICE_INSTRUMENTATION",
  "PINNING_BYPASS_AUTOMATION",
  "ROOT_JAILBREAK_BYPASS_AUTOMATION",
] as const;
export type ProhibitedMobileAction = (typeof PROHIBITED_MOBILE_AUTOMATION)[number];

export function isProhibitedMobileAction(value: string): boolean {
  return (PROHIBITED_MOBILE_AUTOMATION as readonly string[]).includes(value.toUpperCase());
}

/** §53–§61/§69–§74: tool registrations that NEVER execute in this
 *  product surface. Frida's descriptor is DISABLED for normal static
 *  profiles (§70); Objection's is APPROVAL_REQUIRED with no arbitrary
 *  interactive shell (§74). Neither has an adapter. */
export interface MobileDisabledRegistration {
  slug: string;
  name: string;
  capabilities: string[];
  executionState: "DISABLED" | "APPROVAL_REQUIRED";
  reason: string;
}

export const MOBILE_DISABLED_REGISTRATIONS: MobileDisabledRegistration[] = [
  {
    slug: "frida",
    name: "Frida (dynamic instrumentation)",
    capabilities: ["DYNAMIC_INSTRUMENTATION"],
    executionState: "DISABLED",
    reason: "Prompt 17 §70: dynamic instrumentation is DISABLED for normal static profiles. It may run only inside an approved device-lab session with administrator-reviewed, versioned modules (§71–§73) — never arbitrary user-supplied JavaScript (§72/§75). No executing adapter exists in this build.",
  },
  {
    slug: "objection",
    name: "Objection (dynamic instrumentation)",
    capabilities: ["DYNAMIC_INSTRUMENTATION"],
    executionState: "APPROVAL_REQUIRED",
    reason: "Prompt 17 §74: Objection is APPROVAL_REQUIRED and exposes no arbitrary interactive shell through DSRclone. Only governed, pre-approved exploration modules inside an approved lab session (§71–§73). No executing adapter exists in this build.",
  },
];

/** §102: the mobile tool-health surface — every tool the spec names,
 *  with its worker type, risk and approval requirement. */
export interface MobileToolDescriptor {
  slug: string;
  name: string;
  workerType: "MOBILE_STATIC_ANALYSIS" | "MOBILE_DYNAMIC_ANALYSIS" | "CONNECTOR";
  risk: string;
  approvalRequirement: string;
  capabilities: string[];
}

export const MOBILE_TOOL_DESCRIPTORS: MobileToolDescriptor[] = [
  { slug: "mobsf", name: "MobSF", workerType: "CONNECTOR", risk: "LOW", approvalRequirement: "Admin-registered ScannerInstance (§14)", capabilities: ["MOBILE_STATIC_ANALYSIS", "MANIFEST_ANALYSIS", "CODE_ANALYSIS", "BINARY_ANALYSIS", "CERTIFICATE_ANALYSIS", "NETWORK_SECURITY_CONFIG_ANALYSIS"] },
  { slug: "jadx", name: "JADX", workerType: "MOBILE_STATIC_ANALYSIS", risk: "LOW", approvalRequirement: "None (static, sandboxed)", capabilities: ["ANDROID_DECOMPILATION", "STATIC_CODE_EXTRACTION"] },
  { slug: "apktool", name: "apktool", workerType: "MOBILE_STATIC_ANALYSIS", risk: "LOW", approvalRequirement: "None (static, sandboxed)", capabilities: ["APK_RESOURCE_ANALYSIS", "MANIFEST_EXTRACTION", "RESOURCE_EXTRACTION"] },
  { slug: "ghidra", name: "Ghidra", workerType: "MOBILE_STATIC_ANALYSIS", risk: "REVIEW_REQUIRED", approvalRequirement: "Administrator-approved scripts only (§35)", capabilities: ["BINARY_STATIC_ANALYSIS", "NATIVE_LIBRARY_ANALYSIS"] },
  { slug: "adb", name: "ADB (lab devices)", workerType: "MOBILE_DYNAMIC_ANALYSIS", risk: "REVIEW_REQUIRED", approvalRequirement: "Approved lab device + approved session (§58)", capabilities: ["DEVICE_MANAGEMENT", "APP_INSTALLATION", "LOG_COLLECTION", "CONTROLLED_APP_INTERACTION"] },
  { slug: "frida", name: "Frida", workerType: "MOBILE_DYNAMIC_ANALYSIS", risk: "REVIEW_REQUIRED", approvalRequirement: "APPROVE_MOBILE_INSTRUMENTATION + approved module (§71)", capabilities: ["DYNAMIC_INSTRUMENTATION"] },
  { slug: "objection", name: "Objection", workerType: "MOBILE_DYNAMIC_ANALYSIS", risk: "REVIEW_REQUIRED", approvalRequirement: "APPROVE_MOBILE_INSTRUMENTATION + approved module (§71)", capabilities: ["DYNAMIC_INSTRUMENTATION"] },
  { slug: "mitmproxy", name: "mitmproxy", workerType: "MOBILE_DYNAMIC_ANALYSIS", risk: "MODERATE", approvalRequirement: "Lab session only (§62)", capabilities: ["MOBILE_TRAFFIC_CAPTURE", "HTTP_ANALYSIS", "API_DISCOVERY"] },
  { slug: "burp-suite", name: "Burp Suite", workerType: "CONNECTOR", risk: "MODERATE", approvalRequirement: "Admin-registered ScannerInstance; no unrestricted control (§65)", capabilities: ["MOBILE_PROXY_ANALYSIS"] },
];

/** A registered mobile application as the worker/store resolve it
 *  (§4/§10) — identity + the latest build, references only. */
export interface MobileApplicationRecord {
  id: string;
  workspaceId: string;
  name: string;
  platform: MobilePlatformName;
  packageName?: string;
  bundleId?: string;
  environment?: string;
  criticality?: string;
  status: string;
}

export interface MobileBuildRecord {
  id: string;
  applicationId: string;
  workspaceId: string;
  versionName?: string;
  versionCode?: number;
  artifactHash: string;
  artifactFormat: MobileArtifactFormat;
  artifactReference?: string;
  /** Bounded extracted artifacts registered at intake (§6): manifest
   *  / plist / network-security-config text, decompiled snippets,
   *  native library inventory, entitlements. Sanitized at intake. */
  analysisArtifacts?: Record<string, unknown>;
}

/** Connector dependencies (MobSF transport). The transport is wired
 *  ONLY inside a worker against the admin-registered ScannerInstance
 *  (§14) — the production deps leave it empty so the connector
 *  honestly reports NOT_CONFIGURED (§16). */
export interface MobileConnectorDeps {
  applications: {
    getApplication(applicationId: string): Promise<MobileApplicationRecord | undefined>;
    getBuild(buildId: string): Promise<MobileBuildRecord | undefined>;
    getLatestBuild(applicationId: string): Promise<MobileBuildRecord | undefined>;
  };
  transports: {
    /** MobSF: fetch the stored static-analysis report for an artifact
     *  hash from the configured trusted instance. Report retrieval —
     *  artifacts are submitted only to that instance (§15). */
    mobsf?: {
      fetchReport(artifactHash: string): Promise<string | undefined>;
    };
    /** Device lab (§53): governed operations on DSRclone-managed lab
     *  devices ONLY. There is deliberately NO shell method (§59). */
    devices?: {
      listDevices(): Promise<MobileDeviceRecord[]>;
      installApprovedBuild(deviceId: string, buildHash: string): Promise<{ installed: boolean; verifiedHash: boolean }>;
      collectLogs(deviceId: string, applicationRef: string): Promise<string | undefined>;
      resetDevice(deviceId: string): Promise<{ reset: boolean }>;
    };
    /** Traffic lab (§62): read a COMPLETED capture's sanitized flow
     *  metadata from the lab proxy. Metadata only (§66). */
    traffic?: {
      readSession(sessionId: string): Promise<string | undefined>;
    };
  };
}

export interface MobileDeviceRecord {
  id: string;
  name: string;
  platform: MobilePlatformName;
  deviceKind: "EMULATOR" | "PHYSICAL";
  osVersion?: string;
  availability: string;
  health: string;
  dedicatedNetwork: boolean;
}

/** INERT deps for plan-time registration (§16 pattern): no registry,
 *  no transports — connectors report NOT_CONFIGURED, never data. */
export const INERT_MOBILE_DEPS: MobileConnectorDeps = {
  applications: {
    async getApplication() { return undefined; },
    async getBuild() { return undefined; },
    async getLatestBuild() { return undefined; },
  },
  transports: {},
};

export type { NormalizedMobileData };

/** The parsed payload every Prompt 17 adapter produces: findings plus
 *  the normalized mobile payload, dependency components and an SBOM. */
export interface ParsedMobile {
  findings: import("../findings/finding.types").NormalizedFinding[];
  mobile?: NormalizedMobileData;
  components?: import("../findings/finding.types").NormalizedSoftwareComponent[];
  sbom?: import("../findings/finding.types").NormalizedSbom;
  metrics: Record<string, number>;
}

export function emptyParsedMobile(metrics: Record<string, number> = {}): ParsedMobile {
  return { findings: [], metrics };
}
