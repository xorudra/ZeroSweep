/**
 * Prompt 19 — wireless sanitization + identity helpers (§5/§8/§9/§91/§92).
 *
 * Everything observed over the air — SSIDs, vendor strings, capture
 * metadata, sensor names — is attacker-controlled data. An SSID can
 * carry HTML, JavaScript-like text, terminal escapes, invalid Unicode
 * or kilobytes of padding (§92); it may also carry a planted password
 * (§67 discipline: secret-shaped values are redacted by the shared
 * pass). Sanitization happens ONCE, at parse time, on top of the
 * Prompt 17 hostile-content sanitizer — nothing downstream
 * (persistence, API, GUI, logs, shells) ever sees the raw shape.
 * Values are DATA everywhere: they are never interpolated into a
 * command line (§91).
 */
import { createHash, createHmac } from "node:crypto";
import { sanitizeMobileText } from "../mobile/sanitize";

/** IEEE 802.11 caps an SSID at 32 octets; hostile captures may claim
 *  far more — the platform stores a bounded sanitized form (§92). */
export const MAX_SSID_LENGTH = 64;
export const MAX_WIRELESS_STRING = 512;

export function sanitizeWirelessText(value: unknown, maxLen = MAX_WIRELESS_STRING): string {
  if (typeof value !== "string") return "";
  // Strip complete ANSI sequences (CSI + OSC) BEFORE the shared pass:
  // removing only the ESC byte would leave "[31m" residue (§92). The
  // control characters in these patterns are the point — they match
  // the escape sequences being stripped.
  /* eslint-disable no-control-regex */
  const deEscaped = value
    .replace(/\u001b\[[0-9;?]*[A-Za-z]/g, "")
    .replace(/\u001b\][^\u0007\u001b]*(\u0007|\u001b\\)/g, "")
    .replace(/\u001b./g, "");
  /* eslint-enable no-control-regex */
  return sanitizeMobileText(deEscaped, maxLen);
}

/** §6/§92: sanitize an SSID. Hidden SSIDs (empty / all-NUL beacons)
 *  stay hidden — baseline mode never attempts active disclosure (§7). */
export function sanitizeSsid(value: unknown): { ssid: string; hidden: boolean } {
  if (typeof value !== "string") return { ssid: "", hidden: true };
  const stripped = value.replace(/\0/g, "");
  if (stripped.trim().length === 0) return { ssid: "", hidden: true };
  return { ssid: sanitizeWirelessText(stripped, MAX_SSID_LENGTH), hidden: false };
}

/** §5: BSSID identity — normalize any observed MAC form
 *  (aa:bb:cc:dd:ee:ff, AA-BB-CC-..., aabb.ccdd.eeff, bare hex) to
 *  canonical lowercase colon form. Returns undefined for anything
 *  that is not a well-formed 48-bit address: malformed identity is
 *  dropped, never guessed. */
export function normalizeMacAddress(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const hex = value.trim().replace(/[:.\-\s]/g, "");
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return undefined;
  const lower = hex.toLowerCase();
  return [0, 2, 4, 6, 8, 10].map((i) => lower.slice(i, i + 2)).join(":");
}

export const normalizeBssid = normalizeMacAddress;

/** Locally-administered / randomized station addresses (the U/L bit)
 *  are a privacy signal, not identity — stations are pseudonymized
 *  regardless (§9). */
export function isRandomizedMac(mac: string): boolean {
  const first = Number.parseInt(mac.slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) !== 0;
}

/** §9: station pseudonymization. Ordinary UI/reporting carries ONLY
 *  this HMAC fingerprint — stable within a workspace key so repeat
 *  observations correlate, useless outside it. The raw address
 *  requires VIEW_RAW_WIRELESS_CAPTURES and an audited read (§30). */
export function pseudonymizeStationAddress(address: string, workspaceKey: string): string {
  const normalized = normalizeMacAddress(address) ?? address.toLowerCase();
  const mac = createHmac("sha256", workspaceKey).update(`station:${normalized}`).digest("hex");
  return `sta-${mac.slice(0, 16)}`;
}

/** Display masking for BSSID/station addresses in ordinary views
 *  (§73): the OUI prefix stays (vendor context), the device part is
 *  masked. Elevated raw views are a permission + audit decision made
 *  by the API, never by this helper. */
export function maskMacAddress(mac: string): string {
  const n = normalizeMacAddress(mac);
  if (!n) return "**:**:**:**:**:**";
  const parts = n.split(":");
  return `${parts[0]}:${parts[1]}:${parts[2]}:**:**:**`;
}

/** §41: band inference from frequency (preferred) or channel. */
export function inferBand(frequencyMhz?: number, channel?: number): "2.4GHZ" | "5GHZ" | "6GHZ" | undefined {
  if (typeof frequencyMhz === "number" && Number.isFinite(frequencyMhz)) {
    if (frequencyMhz >= 2400 && frequencyMhz < 2500) return "2.4GHZ";
    if (frequencyMhz >= 5000 && frequencyMhz < 5925) return "5GHZ";
    if (frequencyMhz >= 5925 && frequencyMhz <= 7125) return "6GHZ";
    return undefined;
  }
  if (typeof channel === "number" && Number.isFinite(channel)) {
    if (channel >= 1 && channel <= 14) return "2.4GHZ";
    if (channel >= 32 && channel <= 177) return "5GHZ";
    return undefined;
  }
  return undefined;
}

/** Channel → centre frequency where the mapping is standard (§40). */
export function channelToFrequencyMhz(channel?: number, band?: string): number | undefined {
  if (typeof channel !== "number" || !Number.isFinite(channel)) return undefined;
  if (channel >= 1 && channel <= 13) return 2407 + channel * 5;
  if (channel === 14) return 2484;
  if (band === "5GHZ" || (channel >= 32 && channel <= 177)) return 5000 + channel * 5;
  if (band === "6GHZ" && channel >= 1 && channel <= 233) return 5950 + channel * 5;
  return undefined;
}

/** OUI vendor hint from a BSSID — a bounded, curated prefix table.
 *  Vendor is recorded ONLY where reliably inferred (§6); an unknown
 *  OUI stays undefined rather than a guess. */
const OUI_VENDORS: Record<string, string> = {
  "00:0b:86": "Aruba Networks",
  "18:64:72": "Aruba Networks",
  "f0:9f:c2": "Ubiquiti Networks",
  "00:1a:2b": "Example Networks (fixture OUI)",
  "02:00:00": "Locally administered (fixture)",
};

export function inferVendorFromBssid(bssid: string): string | undefined {
  const n = normalizeMacAddress(bssid);
  if (!n) return undefined;
  return OUI_VENDORS[n.slice(0, 8)];
}

export function wirelessSha256Hex(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}
