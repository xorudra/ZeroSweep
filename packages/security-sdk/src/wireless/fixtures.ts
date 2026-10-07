/**
 * Prompt 19 — controlled wireless fixtures (§81).
 *
 * Synthetic data ONLY: documentation SSIDs ("example-corp-wifi"),
 * documentation/vendor OUIs and locally-administered addresses. No
 * real network, sensor, capture or credential exists here. The
 * planted FAKE_WIFI_PSK exists to prove the platform NEVER persists
 * credential material found in tool output (§67): a hostile Kismet
 * record carries it in a "key" field that no parser reads.
 */
import { createHash } from "node:crypto";

export const FAKE_WIFI_PSK = "FAKE_WIFI_PSK_fixture_value_never_persist";

/** Approved-profile BSSIDs used across fixtures/tests. */
export const FIXTURE_AP_WPA2 = "00:0b:86:11:22:33";
export const FIXTURE_AP_WPA3 = "00:0b:86:44:55:66";
export const FIXTURE_AP_GUEST_OPEN = "f0:9f:c2:77:88:99";
export const FIXTURE_AP_WEP = "00:1a:2b:aa:bb:cc";
export const FIXTURE_AP_HIDDEN = "00:0b:86:de:ad:01";
export const FIXTURE_AP_ROGUE = "02:00:00:99:88:77";
export const FIXTURE_STATION_MAC = "3c:22:fb:11:22:33";
export const FIXTURE_CORP_SSID = "example-corp-wifi";

const T0 = 1_760_000_000; // fixed epoch base for deterministic fixtures

function kismetAp(mac: string, ssid: string, crypt: string, channel: string, freq: number, signal: number, offset: number, extra: Record<string, unknown> = {}) {
  return {
    "kismet.device.base.macaddr": mac,
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.channel": channel,
    "kismet.device.base.frequency": freq,
    "kismet.device.base.signal": { "kismet.common.signal.last_signal": signal },
    "kismet.device.base.first_time": T0,
    "kismet.device.base.last_time": T0 + offset,
    "kismet.device.base.crypt": crypt,
    "dot11.device": { "dot11.device.last_beaconed_ssid": ssid },
    ...extra,
  };
}

/** §81/§82: Kismet export — WPA2 AP, WPA3 AP (PMF), open guest AP,
 *  WEP AP, hidden-SSID AP, a rogue suspect (same corp SSID, open),
 *  one station, and a hostile record with a planted PSK + hostile
 *  SSID. The rogue record is sensor-2's view of the same airspace. */
export const KISMET_FIXTURE_JSON = JSON.stringify([
  kismetAp(FIXTURE_AP_WPA2, FIXTURE_CORP_SSID, "WPA2-PSK-CCMP", "6", 2_437_000, -42, 600),
  kismetAp(FIXTURE_AP_WPA3, FIXTURE_CORP_SSID, "WPA3-SAE-GCMP", "36", 5_180_000, -55, 600),
  kismetAp(FIXTURE_AP_GUEST_OPEN, "example-guest-wifi", "None", "1", 2_412_000, -60, 600),
  kismetAp(FIXTURE_AP_WEP, "example-legacy", "WEP", "11", 2_462_000, -70, 600),
  kismetAp(FIXTURE_AP_HIDDEN, "", "WPA2-PSK-CCMP", "6", 2_437_000, -65, 600),
  kismetAp(FIXTURE_AP_ROGUE, FIXTURE_CORP_SSID, "None", "6", 2_437_000, -35, 620),
  {
    "kismet.device.base.macaddr": FIXTURE_STATION_MAC,
    "kismet.device.base.type": "Wi-Fi Client",
    "kismet.device.base.channel": "6",
    "kismet.device.base.frequency": 2_437_000,
    "kismet.device.base.signal": { "kismet.common.signal.last_signal": -48 },
    "kismet.device.base.first_time": T0 + 10,
    "kismet.device.base.last_time": T0 + 590,
    "dot11.device": { "dot11.device.associated_bssid": FIXTURE_AP_WPA2 },
  },
  // Hostile record (§91/§92): markup/ANSI SSID + a planted credential
  // field. The parser sanitizes the SSID and NEVER reads the key.
  kismetAp("00:0b:86:66:77:88", "<script>alert(1)</script>\u001b[31mRED", "WPA2-PSK-CCMP", "6", 2_437_000, -50, 600,
    { "kismet.device.base.key": FAKE_WIFI_PSK }),
]);

/** Second sensor's export (§86): the SAME WPA2 AP observed again —
 *  multi-sensor dedup must yield ONE AP with two observations. */
export const KISMET_FIXTURE_JSON_SENSOR2 = JSON.stringify([
  kismetAp(FIXTURE_AP_WPA2, FIXTURE_CORP_SSID, "WPA2-PSK-CCMP", "6", 2_437_000, -47, 900),
]);

function tsharkLine(epoch: number, bssid: string, ssid: string, channel: string, freq: string, signal: string,
  subtype: string, sa: string, da: string, akm: string, cipher: string, pmf: string, privacy: string): string {
  return [epoch, bssid, ssid, channel, freq, signal, subtype, sa, da, akm, cipher, pmf, privacy].join("\t");
}

/** §81/§83/§89: tshark field output — beacons for WPA2/open/WEP APs,
 *  station data frames, and a 25-frame deauthentication burst inside
 *  one 60s window (passive event evidence; nothing transmitted). */
export const TSHARK_WIRELESS_FIXTURE = (() => {
  const lines: string[] = [];
  lines.push(tsharkLine(T0, FIXTURE_AP_WPA2, FIXTURE_CORP_SSID, "6", "2437", "-42", "0x08", FIXTURE_AP_WPA2, "ff:ff:ff:ff:ff:ff", "PSK", "CCMP", "capable", "1"));
  lines.push(tsharkLine(T0 + 1, FIXTURE_AP_GUEST_OPEN, "example-guest-wifi", "1", "2412", "-60", "0x08", FIXTURE_AP_GUEST_OPEN, "ff:ff:ff:ff:ff:ff", "", "", "", "0"));
  lines.push(tsharkLine(T0 + 2, FIXTURE_AP_WEP, "example-legacy", "11", "2462", "-70", "0x08", FIXTURE_AP_WEP, "ff:ff:ff:ff:ff:ff", "", "", "", "1"));
  lines.push(tsharkLine(T0 + 3, FIXTURE_AP_WPA2, FIXTURE_CORP_SSID, "6", "2437", "-44", "0x20", FIXTURE_STATION_MAC, FIXTURE_AP_WPA2, "", "", "", "1"));
  for (let i = 0; i < 25; i += 1) {
    lines.push(tsharkLine(T0 + 100 + i, FIXTURE_AP_WPA2, "", "6", "2437", "-40", "0x0c", FIXTURE_AP_WPA2, "ff:ff:ff:ff:ff:ff", "", "", "", "1"));
  }
  return lines.join("\n");
})();

/** §23/§67: hcxpcapngtool summary — counts + an AP line + a planted
 *  hashcat-format line that must be COUNTED, never retained. */
export const HCX_SUMMARY_FIXTURE = [
  "session summary",
  "---------------",
  "file name.......................: fixture-capture.pcapng",
  "access points (total)...........: 2",
  "",
  `${FIXTURE_AP_WPA2}  ${FIXTURE_CORP_SSID}`,
  `WPA*01*${"a".repeat(32)}*${FIXTURE_AP_WPA2.replace(/:/g, "")}*${"b".repeat(32)}***`,
].join("\n");

/** §19: aircrack-ng offline inspection output for the fixture capture. */
export const AIRCRACK_INFO_FIXTURE = [
  "Opening fixture-capture.cap",
  "Read 128 packets.",
  "",
  "   #  BSSID              ESSID                     Encryption",
  "",
  `   1  ${FIXTURE_AP_WPA2.toUpperCase()}  ${FIXTURE_CORP_SSID}         WPA2 (1 handshake)`,
  `   2  ${FIXTURE_AP_GUEST_OPEN.toUpperCase()}  example-guest-wifi        No data - WPS disabled`,
  "",
  "Choosing first network as target.",
].join("\n");

/** §27/§83: a synthetic minimal pcap (global header only) — format
 *  proof + intake fixture. No real frames, no credentials. */
export const FIXTURE_PCAP_BYTES: Buffer = (() => {
  const header = Buffer.alloc(24);
  header.writeUInt32LE(0xa1b2c3d4, 0); // magic (little-endian file)
  header.writeUInt16LE(2, 4);
  header.writeUInt16LE(4, 6);
  header.writeInt32LE(0, 8);
  header.writeUInt32LE(0, 12);
  header.writeUInt32LE(65535, 16);
  header.writeUInt32LE(127, 20); // LINKTYPE_IEEE802_11
  return header;
})();

export const FIXTURE_PCAP_SHA256 = createHash("sha256").update(FIXTURE_PCAP_BYTES).digest("hex");

/** §27: a synthetic minimal pcapng (section header block). */
export const FIXTURE_PCAPNG_BYTES: Buffer = (() => {
  const block = Buffer.alloc(28);
  block.writeUInt32LE(0x0a0d0d0a, 0); // SHB type
  block.writeUInt32LE(28, 4); // block total length
  block.writeUInt32LE(0x1a2b3c4d, 8); // byte-order magic
  block.writeUInt16LE(1, 12);
  block.writeUInt16LE(0, 14);
  block.writeInt32LE(-1, 16);
  block.writeInt32LE(-1, 20);
  block.writeUInt32LE(28, 24);
  return block;
})();

/** §84: malformed capture — pcap magic with a truncated header. */
export const FIXTURE_MALFORMED_PCAP_BYTES: Buffer = Buffer.from([0xa1, 0xb2, 0xc3, 0xd4, 0x00, 0x02]);

/** §88: drift scenario — the WPA3 AP re-observed as OPEN. */
export const KISMET_DRIFT_FIXTURE_JSON = JSON.stringify([
  kismetAp(FIXTURE_AP_WPA3, FIXTURE_CORP_SSID, "None", "36", 5_180_000, -50, 1200),
]);
