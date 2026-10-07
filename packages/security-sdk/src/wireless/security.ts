/**
 * Prompt 19 — wireless security-mode normalization (§31–§39).
 *
 * Mode is derived from PROTOCOL EVIDENCE ONLY (RSN/WPA information
 * elements, AKM suites, cipher suites, capability privacy bit) —
 * never from SSID naming (§35: an SSID called "CorpWPA3" proves
 * nothing). The detailed evidence (ciphers, authentication, PMF,
 * WPS) is preserved alongside the normalized mode (§31).
 */
import type { WirelessPmfState, WirelessSecurityMode } from "../findings/finding.types";
import { sanitizeWirelessText } from "./sanitize";

/** Raw security evidence as parsers extract it from beacons/RSN IEs
 *  or survey-tool records. Every field is optional and untrusted. */
export interface WirelessSecurityEvidence {
  /** Beacon capability "privacy" bit / tool-reported encryption text. */
  privacyText?: string;
  /** RSN/WPA version hints: "WPA", "WPA2", "WPA3", "RSN". */
  versions?: string[];
  /** Cipher suites observed: CCMP, TKIP, GCMP, WEP40, WEP104, NONE. */
  ciphers?: string[];
  /** AKM suites observed: PSK, SAE, EAP, OWE, FT-PSK, FT-SAE... */
  akms?: string[];
  /** PMF: "required" | "capable" | absent (§38). */
  pmf?: string;
  /** WPS advertised in beacon/probe metadata (§39). */
  wps?: boolean;
}

export interface NormalizedWirelessSecurity {
  mode: WirelessSecurityMode;
  encryption?: string;
  authentication?: string;
  pmf: WirelessPmfState;
  wpsAdvertised: boolean;
  /** True when both WPA2 and WPA3 AKMs are offered (§36). */
  transitionMode: boolean;
  /** True when any legacy cipher (WEP/TKIP) is in evidence. */
  legacyCipher: boolean;
}

function normList(values: string[] | undefined): string[] {
  return (values ?? []).map((v) => sanitizeWirelessText(v, 32).toUpperCase()).filter((v) => v.length > 0);
}

/** §31–§39: normalize evidence into mode + preserved detail. */
export function normalizeWirelessSecurity(evidence: WirelessSecurityEvidence): NormalizedWirelessSecurity {
  const versions = normList(evidence.versions);
  const ciphers = normList(evidence.ciphers);
  const akms = normList(evidence.akms);
  const privacy = (evidence.privacyText ?? "").toUpperCase();

  const hasWep = ciphers.some((c) => c.startsWith("WEP")) || /\bWEP\b/.test(privacy);
  const hasTkip = ciphers.some((c) => c.includes("TKIP"));
  const hasWpa3 = versions.some((v) => v.includes("WPA3")) || akms.some((a) => a.includes("SAE"));
  const hasWpa2 = versions.some((v) => v === "WPA2" || v === "RSN") || akms.some((a) => a === "PSK" || a.includes("PSK")) || /\bWPA2\b/.test(privacy);
  const hasWpa1 = versions.some((v) => v === "WPA") || /\bWPA\b(?!2|3)/.test(privacy);
  const enterprise = akms.some((a) => a.includes("EAP") || a.includes("802.1X")) || /802\.1X|ENTERPRISE|\bEAP\b/.test(privacy);
  const sae = akms.some((a) => a.includes("SAE"));
  const psk = akms.some((a) => a.includes("PSK"));
  const owe = akms.some((a) => a.includes("OWE"));
  const anySecurity = hasWep || hasWpa3 || hasWpa2 || hasWpa1 || enterprise || sae || psk || owe || ciphers.length > 0;

  const pmf: WirelessPmfState = evidence.pmf === "required" ? "REQUIRED"
    : evidence.pmf === "capable" ? "CAPABLE"
    : evidence.pmf === "not-observed" ? "NOT_OBSERVED"
    : "UNKNOWN";

  const transitionMode = hasWpa3 && hasWpa2 && (sae || psk);
  let mode: WirelessSecurityMode;
  if (!anySecurity && (privacy.includes("OPEN") || privacy === "" || privacy === "NONE" || ciphers.some((c) => c === "NONE"))) {
    mode = owe ? "OPEN" : "OPEN"; // OWE is encrypted-open; detail preserves it
    if (!anySecurity && evidence.privacyText === undefined && ciphers.length === 0 && akms.length === 0 && versions.length === 0) {
      mode = "UNKNOWN";
    }
  } else if (hasWep) {
    mode = "WEP";
  } else if (transitionMode) {
    mode = "TRANSITION";
  } else if (hasWpa3) {
    mode = enterprise ? "ENTERPRISE" : "WPA3";
  } else if (hasWpa2) {
    mode = enterprise ? "ENTERPRISE" : "WPA2";
  } else if (hasWpa1) {
    mode = enterprise ? "ENTERPRISE" : "WPA";
  } else if (enterprise) {
    mode = "ENTERPRISE";
  } else {
    mode = "UNKNOWN";
  }

  const encryption = ciphers.length > 0 ? ciphers.join("+") : hasWep ? "WEP" : undefined;
  const authentication = owe ? "OWE"
    : enterprise ? "EAP/802.1X"
    : sae && psk ? "SAE+PSK"
    : sae ? "SAE"
    : psk ? "PSK"
    : mode === "OPEN" ? "OPEN"
    : undefined;

  return {
    mode,
    ...(encryption ? { encryption } : {}),
    ...(authentication ? { authentication } : {}),
    pmf,
    wpsAdvertised: evidence.wps === true,
    transitionMode,
    legacyCipher: hasWep || hasTkip,
  };
}

/** Parse a survey-tool privacy string (Kismet-style, e.g.
 *  "WPA2-PSK-CCMP", "WPA3-SAE-GCMP", "None", "WEP") into evidence. */
export function securityEvidenceFromPrivacyText(text: string | undefined): WirelessSecurityEvidence {
  if (!text) return {};
  const t = text.toUpperCase();
  const versions: string[] = [];
  if (/WPA3/.test(t)) versions.push("WPA3");
  if (/WPA2|RSN/.test(t)) versions.push("WPA2");
  if (/\bWPA\b/.test(t) && !/WPA2|WPA3/.test(t)) versions.push("WPA");
  const ciphers: string[] = [];
  if (/CCMP|AES/.test(t)) ciphers.push("CCMP");
  if (/TKIP/.test(t)) ciphers.push("TKIP");
  if (/GCMP/.test(t)) ciphers.push("GCMP");
  if (/WEP/.test(t)) ciphers.push("WEP104");
  const akms: string[] = [];
  if (/SAE/.test(t)) akms.push("SAE");
  if (/PSK/.test(t)) akms.push("PSK");
  if (/802\.1X|EAP|ENTERPRISE/.test(t)) akms.push("EAP");
  if (/OWE/.test(t)) akms.push("OWE");
  return { privacyText: text, versions, ciphers, akms, wps: /WPS/.test(t) };
}

/** §57: encryption-strength ordering for risk + drift comparisons.
 *  Higher is stronger. UNKNOWN ranks below OPEN: an unclassifiable
 *  posture is a review item, not a pass. */
export const SECURITY_MODE_STRENGTH: Record<WirelessSecurityMode, number> = {
  UNKNOWN: 0, OPEN: 1, WEP: 2, WPA: 3, PERSONAL: 3, WPA2: 4, TRANSITION: 4, WPA3: 5, ENTERPRISE: 6,
};

export function isSecurityDowngrade(from: WirelessSecurityMode, to: WirelessSecurityMode): boolean {
  return SECURITY_MODE_STRENGTH[to] < SECURITY_MODE_STRENGTH[from];
}
