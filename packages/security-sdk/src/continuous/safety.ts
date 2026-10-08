import type { AutomationSafetyClass } from "./types";

/**
 * Safe-automation classification (Prompt 22 §9–§11, §103–§106, §122).
 *
 * This is a CLOSED classification over every AssessmentProfile the
 * platform knows. A profile that is not SAFE_AUTOMATED can never become
 * a recurring unattended job — schedule creation refuses it, and the
 * scheduler re-checks the class at fire time (defense in depth: a row
 * written by any other path is still blocked at materialization).
 *
 * Classification rationale (§10/§11):
 * - SAFE_AUTOMATED: passive recon, approved HTTP checks, Nuclei safe
 *   templates, TLS checks, safe Nmap profiles, read-only cloud posture,
 *   container image scanning, SAST/SCA/secret scanning, Kubernetes
 *   configuration analysis, mobile + binary STATIC analysis, wireless
 *   PASSIVE monitoring, read-only identity posture checks.
 * - APPROVAL_REQUIRED: heavier active or privileged profiles whose
 *   manual runs are approval-gated (comprehensive web/network probing,
 *   internal engagements, privileged host benchmarks, wireless lab
 *   validation). A human approves each run — never unattended.
 * - MANUAL_ONLY: profiles whose composition cannot be statically
 *   proven safe (CUSTOM).
 * - PROHIBITED_AUTOMATION: runtime/debugging/instrumentation profiles
 *   (§122: binary runtime debugging and dynamic mobile instrumentation
 *   must never be scheduled).
 */

export interface ProfileClassification {
  profile: string;
  safetyClass: AutomationSafetyClass;
  /** True only for SAFE_AUTOMATED — the only class a schedule may run. */
  schedulable: boolean;
  reason: string;
}

const SAFE = (reason: string): Omit<ProfileClassification, "profile"> => ({
  safetyClass: "SAFE_AUTOMATED", schedulable: true, reason,
});
const APPROVAL = (reason: string): Omit<ProfileClassification, "profile"> => ({
  safetyClass: "APPROVAL_REQUIRED", schedulable: false, reason,
});
const MANUAL = (reason: string): Omit<ProfileClassification, "profile"> => ({
  safetyClass: "MANUAL_ONLY", schedulable: false, reason,
});
const PROHIBITED = (reason: string): Omit<ProfileClassification, "profile"> => ({
  safetyClass: "PROHIBITED_AUTOMATION", schedulable: false, reason,
});

const SAFE_REASON = "passive / read-only / static analysis only (§10)";
const PROFILE_CLASSES: Record<string, Omit<ProfileClassification, "profile">> = {
  PASSIVE_RECON: SAFE("passive reconnaissance only (§10)"),
  WEB_BASELINE: SAFE("approved HTTP checks + Nuclei safe templates + TLS (§10)"),
  API_ASSESSMENT: SAFE("governed API checks — destructive operations are policy-excluded by the operation engine (§10)"),
  NETWORK_DISCOVERY: SAFE("safe discovery profile (§10)"),
  NETWORK_BASELINE: SAFE("safe Nmap profile — intrusive/brute/DoS NSE classes are policy-excluded (§10)"),
  SOURCE_CODE: SAFE("SAST/SCA/secret scanning — target code is never executed (§10)"),
  SOURCE_BASELINE: SAFE(SAFE_REASON),
  SOURCE_COMPREHENSIVE: SAFE("static analysis only — target code is never executed (§10)"),
  SECRETS_ONLY: SAFE(SAFE_REASON),
  DEPENDENCIES_ONLY: SAFE(SAFE_REASON),
  SAST_ONLY: SAFE(SAFE_REASON),
  CONTAINER: SAFE("container image scanning — images are never executed (§10)"),
  CONTAINER_BASELINE: SAFE(SAFE_REASON),
  CONTAINER_COMPREHENSIVE: SAFE("static image + configuration analysis only (§10)"),
  SBOM_ONLY: SAFE(SAFE_REASON),
  IMAGE_VULNERABILITIES_ONLY: SAFE(SAFE_REASON),
  CONTAINER_MISCONFIG_ONLY: SAFE(SAFE_REASON),
  KUBERNETES_BASELINE: SAFE("Kubernetes configuration analysis (§10)"),
  KUBERNETES_COMPREHENSIVE: SAFE("Kubernetes configuration analysis (§10)"),
  CLOUD: SAFE("read-only cloud posture (§10)"),
  CLOUD_INVENTORY: SAFE("read-only cloud inventory (§10)"),
  CLOUD_BASELINE: SAFE("read-only cloud posture (§10)"),
  CLOUD_COMPREHENSIVE: SAFE("read-only cloud posture (§10)"),
  IAM_REVIEW: SAFE("read-only IAM posture (§10)"),
  PUBLIC_EXPOSURE_REVIEW: SAFE("read-only exposure review (§10)"),
  COMPLIANCE_ASSESSMENT: SAFE("read-only compliance posture (§10)"),
  IAC_TO_CLOUD_CORRELATION: SAFE("read-only correlation (§10)"),
  AD_INVENTORY: SAFE("read-only identity inventory (§10)"),
  AD_BASELINE: SAFE("read-only identity posture checks (§10)"),
  AD_COMPREHENSIVE: SAFE("read-only identity posture — credential attacks are DISABLED descriptors, never executed (§10)"),
  ADCS_POSTURE: SAFE("read-only certificate posture (§10)"),
  SMB_POSTURE: SAFE("read-only SMB posture (§10)"),
  IDENTITY_GRAPH: SAFE("read-only identity graph collection (§10)"),
  ATTACK_PATH_ANALYSIS: SAFE("defensive read-only attack-path analysis (§10)"),
  MOBILE: SAFE("mobile static analysis (§10)"),
  MOBILE_STATIC_BASELINE: SAFE("mobile static analysis (§10)"),
  MOBILE_STATIC_COMPREHENSIVE: SAFE("mobile static analysis (§10)"),
  MOBILE_SECRETS_ONLY: SAFE(SAFE_REASON),
  MOBILE_BINARY_ANALYSIS: SAFE("static binary analysis of the app artifact (§10)"),
  BINARY_METADATA_ONLY: SAFE("static metadata only (§10)"),
  BINARY_BASELINE: SAFE("static analysis only (§10)"),
  BINARY_ASSESSMENT: SAFE("static analysis only (§10)"),
  BINARY_COMPREHENSIVE_STATIC: SAFE("comprehensive STATIC analysis — the artifact is never executed (§103)"),
  BINARY_DEPENDENCY_ANALYSIS: SAFE(SAFE_REASON),
  WIRELESS_PASSIVE_BASELINE: SAFE("wireless passive monitoring — nothing transmits (§105)"),
  WIRELESS_PASSIVE_COMPREHENSIVE: SAFE("wireless passive monitoring — nothing transmits (§10)"),
  PCAP_ANALYSIS_ONLY: SAFE("offline capture analysis (§10)"),
  WIRELESS_COMPLIANCE: SAFE("passive posture compliance (§10)"),

  WEB_COMPREHENSIVE: APPROVAL("comprehensive active web probing is approval-gated per run — never unattended"),
  NETWORK_COMPREHENSIVE: APPROVAL("comprehensive network probing is approval-gated per run — never unattended"),
  NETWORK_INTERNAL: APPROVAL("internal engagements require an approved internal engagement per run — never unattended"),
  DOCKER_HOST_BASELINE: APPROVAL("privileged host benchmarks run only on privileged workers under per-run approval"),
  CLOUD_NATIVE_FULL: APPROVAL("includes privileged host benchmarks — approval-gated per run"),
  WIRELESS_LAB_VALIDATION: APPROVAL("governed lab validation is approval-gated per run — never unattended"),

  CUSTOM: MANUAL("custom profile composition cannot be statically proven safe — manual runs only"),

  BINARY_CONTROLLED_DEBUG: PROHIBITED("binary runtime debugging must never become unattended automation (§103/§122)"),
  MOBILE_DYNAMIC_CONTROLLED: PROHIBITED("dynamic mobile instrumentation must never become unattended automation (§104/§122)"),
  MOBILE_FULL_CONTROLLED: PROHIBITED("dynamic mobile instrumentation must never become unattended automation (§122)"),
};

export function classifyProfile(profile: string): ProfileClassification {
  const found = PROFILE_CLASSES[profile];
  if (found) return { profile, ...found };
  // Unknown profiles fail CLOSED: never schedulable.
  return {
    profile,
    safetyClass: "MANUAL_ONLY",
    schedulable: false,
    reason: `unknown profile "${profile}" — fail-closed: not schedulable`,
  };
}

export function isSchedulableProfile(profile: string): boolean {
  return classifyProfile(profile).schedulable;
}

/**
 * §11 never-auto-schedule technique/action names. Used to refuse
 * schedules, workflow actions and retest requests that NAME a
 * prohibited capability even outside the profile system (e.g. a
 * workflow called "nightly wifite run"). Normalization mirrors the
 * Prompt 16 technique classifier (case/space/dash-insensitive,
 * substring-aware for squashed names ≥ 6 chars).
 */
const PROHIBITED_AUTOMATION_NAMES: readonly string[] = [
  "password spraying", "credential stuffing", "brute force", "kerberoasting",
  "as-rep roasting", "asrep roasting", "ntlm relay", "credential dumping",
  "rce exploitation", "remote code execution exploit", "privilege escalation",
  "lateral movement", "persistence", "deauthentication", "deauth attack",
  "evil twin", "wi-fi cracking", "wifi cracking", "wpa cracking",
  "frida instrumentation", "arbitrary instrumentation", "debugger execution",
  "destructive api", "password cracking", "hash cracking", "wifite",
  "mimikatz", "lsass dumping", "pass the hash", "golden ticket",
];

function squashName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "");
}

const SQUASHED_PROHIBITED = PROHIBITED_AUTOMATION_NAMES.map(squashName);

export function classifyAutomationName(name: string): AutomationSafetyClass {
  const squashed = squashName(name);
  if (!squashed) return "MANUAL_ONLY";
  for (const p of SQUASHED_PROHIBITED) {
    if (squashed === p || squashed.includes(p) || (p.includes(squashed) && squashed.length >= 6)) {
      return "PROHIBITED_AUTOMATION";
    }
  }
  return "MANUAL_ONLY";
}

export function isProhibitedAutomationName(name: string): boolean {
  return classifyAutomationName(name) === "PROHIBITED_AUTOMATION";
}
