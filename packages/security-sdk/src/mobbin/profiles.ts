import type { MobbinProfile, MobbinProfileDefinition } from "./types";

/**
 * Prompt 35 §15/§16 — V2 analysis profiles.
 *
 * Static by default (§16): an artifact upload triggers NO dynamic
 * instrumentation. Dynamic modules exist only in the *_DYNAMIC_SAFE
 * profiles and still pass the §71 gate in the plan builder — a
 * profile naming dynamic modules never authorizes them by itself.
 */
const ANDROID_STATIC_MODULES = [
  "INGEST", "CLASSIFY", "MANIFEST_ANALYSIS", "STATIC_ANALYSIS",
  "DEPENDENCY_ANALYSIS", "SECRET_ANALYSIS", "BINARY_HARDENING",
  "CRYPTO_ANALYSIS", "STORAGE_ANALYSIS", "WEBVIEW_ANALYSIS",
  "NETWORK_CONFIG_ANALYSIS",
] as const;

const IOS_STATIC_MODULES = [
  "INGEST", "CLASSIFY", "MANIFEST_ANALYSIS", "STATIC_ANALYSIS",
  "DEPENDENCY_ANALYSIS", "SECRET_ANALYSIS", "BINARY_HARDENING",
  "CRYPTO_ANALYSIS", "STORAGE_ANALYSIS", "NETWORK_CONFIG_ANALYSIS",
] as const;

export const MOBBIN_PROFILE_DEFINITIONS: Record<MobbinProfile, MobbinProfileDefinition> = {
  MOBILE_STATIC: {
    profile: "MOBILE_STATIC", platform: "ANY",
    staticModules: [...ANDROID_STATIC_MODULES], dynamicModules: [], dynamic: false,
    description: "Static-only analysis for either platform (§16 default posture).",
  },
  MOBILE_STANDARD: {
    profile: "MOBILE_STANDARD", platform: "ANY",
    staticModules: [...ANDROID_STATIC_MODULES], dynamicModules: [], dynamic: false,
    description: "Full static pipeline: manifest, code rules, dependencies, secrets, hardening, crypto, storage, WebView, network config.",
  },
  ANDROID_STATIC: {
    profile: "ANDROID_STATIC", platform: "ANDROID",
    staticModules: [...ANDROID_STATIC_MODULES], dynamicModules: [], dynamic: false,
    description: "Android static analysis (manifest/permissions/components + code + native libraries).",
  },
  ANDROID_DYNAMIC_SAFE: {
    profile: "ANDROID_DYNAMIC_SAFE", platform: "ANDROID",
    staticModules: [...ANDROID_STATIC_MODULES],
    dynamicModules: ["RUNTIME_OBSERVATION", "TRAFFIC_ANALYSIS", "DYNAMIC_STORAGE_ANALYSIS", "LOG_EXPOSURE_ANALYSIS"],
    dynamic: true,
    description: "Android static + governed lab dynamic observation. Dynamic modules run only inside an approved session on an authorized device (§71–§87).",
  },
  IOS_STATIC: {
    profile: "IOS_STATIC", platform: "IOS",
    staticModules: [...IOS_STATIC_MODULES], dynamicModules: [], dynamic: false,
    description: "iOS static analysis (Info.plist, entitlements, ATS, URL schemes, signing, Mach-O metadata).",
  },
  IOS_DYNAMIC_SAFE: {
    profile: "IOS_DYNAMIC_SAFE", platform: "IOS",
    staticModules: [...IOS_STATIC_MODULES],
    dynamicModules: ["RUNTIME_OBSERVATION", "TRAFFIC_ANALYSIS", "LOG_EXPOSURE_ANALYSIS"],
    dynamic: true,
    description: "iOS static + governed lab dynamic observation on authorized simulator/test devices only (§71).",
  },
  BINARY_STATIC: {
    profile: "BINARY_STATIC", platform: "BINARY",
    staticModules: ["INGEST", "CLASSIFY", "STATIC_ANALYSIS", "DEPENDENCY_ANALYSIS", "SECRET_ANALYSIS"],
    dynamicModules: [], dynamic: false,
    description: "Binary static analysis: format, imports/exports, strings, symbols, dependencies (§51–§65).",
  },
  BINARY_HARDENING: {
    profile: "BINARY_HARDENING", platform: "BINARY",
    staticModules: ["INGEST", "CLASSIFY", "BINARY_HARDENING"],
    dynamicModules: [], dynamic: false,
    description: "Hardening-only pass (checksec-class evidence): NX/PIE/RELRO/canary/FORTIFY (§54).",
  },
  TARGETED_MOBILE_VERIFICATION: {
    profile: "TARGETED_MOBILE_VERIFICATION", platform: "ANY",
    staticModules: ["INGEST", "CLASSIFY", "STATIC_ANALYSIS"],
    dynamicModules: [], dynamic: false,
    description: "Prompt 31 fix verification: re-run the targeted static check for one rule against the NEW build (§107).",
  },
};

export function mobbinProfileDefinition(profile: string): MobbinProfileDefinition | null {
  return (MOBBIN_PROFILE_DEFINITIONS as Record<string, MobbinProfileDefinition>)[profile] ?? null;
}

/** Bounded analysis limits (§28/§56/§58): snippets, strings and
 *  components are capped — the platform never dumps an entire
 *  decompiled application or millions of strings into the database. */
export const MOBBIN_DEFAULT_LIMITS = { maxFindings: 2000, maxStrings: 5000, maxComponents: 1000 } as const;
