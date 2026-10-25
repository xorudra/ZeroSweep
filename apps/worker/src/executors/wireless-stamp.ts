/**
 * Prompt 19 §52/§53: canonical wireless finding identity, shared by
 * the worker stores. Processed findings from wireless adapters or
 * the platform posture analysis receive their identity here —
 * environment, the AP's BSSID (§5) and the §53 canonical fingerprint
 * (environment + BSSID + rule + security mode + finding class; never
 * the SSID alone). The stamped fingerprint becomes the correlation
 * key, so the same posture issue observed by two sensors converges
 * on ONE canonical finding with every observation preserved (§54).
 */
import {
  WIRELESS_SLUGS, wirelessFindingFingerprint, type WirelessFindingType,
} from "@zerosweep/security-sdk";
import type { ProcessedFinding } from "./result-processor";

export interface WirelessScanIdentity {
  environmentId: string;
  environmentRef?: string;
}

export function isWirelessProcessedFinding(f: ProcessedFinding): boolean {
  return f.wirelessFindingType !== undefined
    || (WIRELESS_SLUGS as readonly string[]).includes(f.sourceTool)
    || (f.ruleId?.startsWith("WIRELESS_") ?? false)
    || f.sourceTool === "wireless-posture";
}

function defaultFindingType(f: ProcessedFinding): WirelessFindingType {
  if (f.wirelessFindingType) return f.wirelessFindingType as WirelessFindingType;
  if ((f.ruleId ?? "").includes("ROGUE")) return "WIRELESS_ROGUE_AP_FINDING";
  if ((f.ruleId ?? "").includes("WPS") || (f.ruleId ?? "").includes("AUTH")) return "WIRELESS_AUTH_FINDING";
  if ((f.ruleId ?? "").includes("EVENT")) return "WIRELESS_SECURITY_EVENT";
  if ((f.ruleId ?? "").includes("PMF") || (f.ruleId ?? "").includes("TRANSITION")) return "WIRELESS_CONFIGURATION_FINDING";
  return "WIRELESS_ENCRYPTION_FINDING";
}

export function stampWirelessFindings(findings: ProcessedFinding[], identity: WirelessScanIdentity): ProcessedFinding[] {
  return findings.map((f) => {
    if (!isWirelessProcessedFinding(f)) return f;
    const findingType = defaultFindingType(f);
    const bssid = f.wirelessBssid ?? f.host ?? "unknown-bssid";
    const stamped: ProcessedFinding = {
      ...f,
      wirelessEnvironmentId: identity.environmentId,
      wirelessBssid: bssid,
      wirelessFindingType: findingType,
    };
    // Adapter/posture findings may arrive without a security-mode
    // component; the fingerprint inputs are (environment, BSSID,
    // rule, mode, class) — mode falls back to the title-neutral
    // "POSTURE" bucket when a producer did not record one (§53).
    const fingerprint = f.wirelessFingerprint ?? wirelessFindingFingerprint({
      environmentId: identity.environmentId,
      bssid,
      rule: f.ruleId ?? f.title,
      securityMode: (f as { wirelessSecurityMode?: string }).wirelessSecurityMode ?? "POSTURE",
      findingClass: findingType,
    });
    stamped.wirelessFingerprint = fingerprint;
    stamped.fingerprint = fingerprint;
    return stamped;
  });
}
