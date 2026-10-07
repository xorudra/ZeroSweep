/**
 * Prompt 19 — wireless retesting (§59).
 *
 * A wireless finding is retested by NEW PASSIVE OBSERVATION: the
 * finding's §53 fingerprint is recomputed over the fresh inventory
 * and the verdict is evidence-based — RESOLVED only when a fresh
 * observation of the same BSSID no longer reproduces the issue,
 * STILL_PRESENT when it does, and INCONCLUSIVE when the AP was not
 * observed at all (absence of observation is not remediation).
 */
import type { NormalizedWirelessAccessPoint } from "../findings/finding.types";
import { analyzeWirelessEncryption, type WirelessAnalysisContext } from "./analysis";

export interface WirelessRetestVerdict {
  fingerprint: string;
  rule: string;
  bssid: string;
  verdict: "RESOLVED" | "STILL_PRESENT" | "INCONCLUSIVE";
  reason: string;
}

export function planWirelessRetest(
  previous: { fingerprint: string; rule: string; bssid: string; securityMode: string }[],
  currentAps: NormalizedWirelessAccessPoint[],
  ctx: WirelessAnalysisContext,
): WirelessRetestVerdict[] {
  const freshFindings = analyzeWirelessEncryption(currentAps, ctx);
  const freshFingerprints = new Set(freshFindings.map((f) => f.wirelessFingerprint));
  const observed = new Map(currentAps.map((a) => [a.bssid.toLowerCase(), a]));
  return previous.map((p): WirelessRetestVerdict => {
    const ap = observed.get(p.bssid.toLowerCase());
    if (!ap) {
      return {
        fingerprint: p.fingerprint, rule: p.rule, bssid: p.bssid, verdict: "INCONCLUSIVE",
        reason: "the AP was not observed in the retest session — absence of observation is not remediation (§59)",
      };
    }
    if (freshFingerprints.has(p.fingerprint)) {
      return {
        fingerprint: p.fingerprint, rule: p.rule, bssid: p.bssid, verdict: "STILL_PRESENT",
        reason: `fresh passive observation of ${p.bssid} reproduces the issue (mode ${ap.securityMode})`,
      };
    }
    return {
      fingerprint: p.fingerprint, rule: p.rule, bssid: p.bssid, verdict: "RESOLVED",
      reason: `fresh passive observation of ${p.bssid} (mode ${ap.securityMode}) no longer reproduces the issue`,
    };
  });
}
