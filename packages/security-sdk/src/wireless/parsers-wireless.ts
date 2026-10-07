/**
 * Prompt 19 — wireless parsers (§18/§23/§24/§27/§81–§85).
 *
 * Parsers translate tool output into the normalized wireless model.
 * Discipline:
 *  - Every string passes the hostile-content sanitizer (§92); every
 *    identity is a validated BSSID (§5); stations are pseudonymized
 *    at parse time (§9) — raw station addresses never leave a parser
 *    in ordinary payloads.
 *  - Credential-shaped fields in tool output (a "key"/"psk"/"eapol"
 *    blob a hostile capture plants) are NEVER read into the model:
 *    authentication material is counted, never extracted (§67).
 *  - Malformed input fails CLOSED: parsers return an empty payload
 *    with a parserFailure metric, never a partial invention (§84).
 */
import type {
  NormalizedWirelessAccessPoint, NormalizedWirelessChannelObservation,
  NormalizedWirelessData, NormalizedWirelessObservation, NormalizedWirelessSecurityEvent,
  NormalizedWirelessStation,
} from "../findings/finding.types";
import { mobNum, mobRec, parseBoundedMobileJson } from "../mobile/sanitize";
import {
  channelToFrequencyMhz, inferBand, inferVendorFromBssid, normalizeBssid, normalizeMacAddress,
  pseudonymizeStationAddress, sanitizeSsid,
} from "./sanitize";
import { normalizeWirelessSecurity, securityEvidenceFromPrivacyText } from "./security";
import { emptyParsedWireless, type ParsedWireless } from "./types";

export interface WirelessParserContext {
  toolSlug: string;
  /** Sensor reference the observations belong to (§10/§11). */
  sensorRef: string;
  /** Workspace key for station pseudonymization (§9). */
  workspaceKey: string;
  /** Fallback timestamp for records without their own. */
  observedAt?: string;
}

function isoFromEpochSeconds(v: unknown, fallback: string): string {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  if (Number.isFinite(n) && n > 0) return new Date(n * 1000).toISOString();
  return fallback;
}

function num(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim().length > 0) {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function buildAp(partial: Partial<NormalizedWirelessAccessPoint> & { bssid: string; source: string }): NormalizedWirelessAccessPoint {
  const band = partial.band ?? inferBand(partial.frequencyMhz, partial.channel);
  return {
    ssid: "",
    ssidHidden: true,
    pmf: "UNKNOWN",
    wpsAdvertised: false,
    firstSeen: partial.firstSeen ?? new Date(0).toISOString(),
    lastSeen: partial.lastSeen ?? new Date(0).toISOString(),
    securityMode: "UNKNOWN",
    ...partial,
    ...(band ? { band } : {}),
    ...(!partial.frequencyMhz && partial.channel ? { frequencyMhz: channelToFrequencyMhz(partial.channel, band) } : {}),
  };
}

function channelObservations(aps: NormalizedWirelessAccessPoint[], source: string): NormalizedWirelessChannelObservation[] {
  const byChannel = new Map<string, NormalizedWirelessChannelObservation>();
  for (const ap of aps) {
    if (ap.channel === undefined || !ap.band) continue;
    const key = `${ap.band}:${ap.channel}`;
    const existing = byChannel.get(key);
    if (existing) {
      existing.apCount += 1;
      if (ap.signalDbm !== undefined) existing.maxSignalDbm = Math.max(existing.maxSignalDbm ?? -100, ap.signalDbm);
    } else {
      byChannel.set(key, {
        channel: ap.channel, band: ap.band, apCount: 1, source,
        ...(ap.signalDbm !== undefined ? { maxSignalDbm: ap.signalDbm } : {}),
      });
    }
  }
  return [...byChannel.values()];
}

function finalize(data: Omit<NormalizedWirelessData, "source">, source: string, extraMetrics: Record<string, number> = {}): ParsedWireless {
  return {
    findings: [],
    wireless: { ...data, source },
    metrics: {
      accessPoints: data.accessPoints.length,
      stations: data.stations.length,
      observations: data.observations.length,
      securityEvents: data.securityEvents.length,
      framesProcessed: data.framesProcessed,
      authenticationMaterialCount: data.authenticationMaterialCount,
      ...extraMetrics,
    },
  };
}

// ── Kismet (§16–§18) ────────────────────────────────────────────────

/**
 * Kismet device-export parser. Input: a JSON array of device records
 * (the normalized Kismet export subset DSRclone consumes). AP records
 * carry dot11 beacon metadata; client records become pseudonymized
 * station observations. Fields a hostile record plants for credential
 * material ("key", "psk", "eapol", "password" anywhere in the record)
 * are never read — the parser only picks its allowlisted fields.
 */
export function parseKismetDevices(text: string, ctx: WirelessParserContext): ParsedWireless {
  const parsed = parseBoundedMobileJson(text, { what: "kismet-devices" });
  if (!Array.isArray(parsed)) return emptyParsedWireless({ parserFailures: 1 });
  const fallbackTs = ctx.observedAt ?? new Date().toISOString();
  const aps = new Map<string, NormalizedWirelessAccessPoint>();
  const stations: NormalizedWirelessStation[] = [];
  const observations: NormalizedWirelessObservation[] = [];

  for (const raw of parsed) {
    const rec = mobRec(raw);
    const bssid = normalizeBssid(rec["kismet.device.base.macaddr"]);
    if (!bssid) continue;
    const type = typeof rec["kismet.device.base.type"] === "string" ? rec["kismet.device.base.type"] : "";
    const signal = mobRec(rec["kismet.device.base.signal"]);
    const signalDbm = mobNum(signal["kismet.common.signal.last_signal"]);
    const firstSeen = isoFromEpochSeconds(rec["kismet.device.base.first_time"], fallbackTs);
    const lastSeen = isoFromEpochSeconds(rec["kismet.device.base.last_time"], fallbackTs);
    const channel = num(rec["kismet.device.base.channel"]);
    const freqKhz = num(rec["kismet.device.base.frequency"]);
    const frequencyMhz = freqKhz !== undefined ? (freqKhz > 100_000 ? Math.round(freqKhz / 1000) : freqKhz) : undefined;

    if (/client|station/i.test(type)) {
      const dot11 = mobRec(rec["dot11.device"]);
      const assoc = normalizeBssid(dot11["dot11.device.associated_bssid"]);
      stations.push({
        addressFingerprint: pseudonymizeStationAddress(bssid, ctx.workspaceKey),
        ...(assoc ? { associatedBssid: assoc } : {}),
        firstSeen, lastSeen,
        ...(signalDbm !== undefined ? { signalDbm } : {}),
        source: ctx.toolSlug,
      });
      continue;
    }
    if (!/ap|bridge/i.test(type) && type !== "") continue;
    const dot11 = mobRec(rec["dot11.device"]);
    const { ssid, hidden } = sanitizeSsid(dot11["dot11.device.last_beaconed_ssid"] ?? rec["kismet.device.base.commonname"]);
    const crypt = typeof rec["kismet.device.base.crypt"] === "string" ? rec["kismet.device.base.crypt"] : undefined;
    const sec = normalizeWirelessSecurity(securityEvidenceFromPrivacyText(crypt));
    const vendor = inferVendorFromBssid(bssid);
    const ap = buildAp({
      bssid, ssid, ssidHidden: hidden,
      ...(vendor ? { vendor } : {}),
      ...(channel !== undefined ? { channel } : {}),
      ...(frequencyMhz !== undefined ? { frequencyMhz } : {}),
      securityMode: sec.mode,
      ...(sec.encryption ? { encryption: sec.encryption } : {}),
      ...(sec.authentication ? { authentication: sec.authentication } : {}),
      pmf: sec.pmf, wpsAdvertised: sec.wpsAdvertised,
      ...(signalDbm !== undefined ? { signalDbm } : {}),
      firstSeen, lastSeen, source: ctx.toolSlug,
    });
    const prev = aps.get(bssid);
    if (!prev || ap.lastSeen > prev.lastSeen) aps.set(bssid, ap);
    else if (prev.ssidHidden && !ap.ssidHidden) aps.set(bssid, { ...prev, ssid: ap.ssid, ssidHidden: false });
    observations.push({
      timestamp: lastSeen, sensorRef: ctx.sensorRef,
      ...(channel !== undefined ? { channel } : {}),
      bssid, ssid, securityMode: sec.mode,
      ...(signalDbm !== undefined ? { signalDbm } : {}),
      source: ctx.toolSlug,
    });
  }

  const apList = [...aps.values()];
  return finalize({
    accessPoints: apList, stations, observations,
    channelObservations: channelObservations(apList, ctx.toolSlug),
    securityEvents: [], authenticationMaterialCount: 0, framesProcessed: 0,
  }, ctx.toolSlug);
}

// ── tshark wireless fields (§24) ────────────────────────────────────

/**
 * tshark `-T fields` parser for the FIXED platform field set (§78 —
 * the filter/field list is a platform constant, never user input):
 *   frame.time_epoch, wlan.bssid, wlan.ssid, wlan_radio.channel,
 *   wlan_radio.frequency, radiotap.dbm_antsignal, wlan.fc.type_subtype,
 *   wlan.sa, wlan.da, wlan.rsn.akm, wlan.rsn.cipher, wlan.rsn.pmf,
 *   wlan.fixed.capabilities.privacy
 * Beacon/probe-response frames build AP inventory (the privacy bit
 * distinguishes OPEN from WEP where no RSN IE exists); deauth/disassoc
 * bursts become passive security events (§47/§49: a burst threshold
 * must be crossed — a single frame never claims an attack); data-frame
 * transmitters become pseudonymized stations.
 */
export const TSHARK_WIRELESS_FIELDS = [
  "frame.time_epoch", "wlan.bssid", "wlan.ssid", "wlan_radio.channel", "wlan_radio.frequency",
  "radiotap.dbm_antsignal", "wlan.fc.type_subtype", "wlan.sa", "wlan.da",
  "wlan.rsn.akm", "wlan.rsn.cipher", "wlan.rsn.pmf", "wlan.fixed.capabilities.privacy",
] as const;

export const DEAUTH_BURST_THRESHOLD = 20; // frames per BSSID per 60 s window

export function parseTsharkWirelessFields(text: string, ctx: WirelessParserContext): ParsedWireless {
  if (typeof text !== "string") return emptyParsedWireless({ parserFailures: 1 });
  const fallbackTs = ctx.observedAt ?? new Date().toISOString();
  const aps = new Map<string, NormalizedWirelessAccessPoint>();
  const stationMap = new Map<string, NormalizedWirelessStation>();
  const observations: NormalizedWirelessObservation[] = [];
  const deauthWindows = new Map<string, number[]>(); // bssid -> epochs
  const disassocWindows = new Map<string, number[]>();
  let frames = 0;

  for (const line of text.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const f = line.split("\t");
    if (f.length < 13) continue;
    frames += 1;
    const epoch = num(f[0]);
    const ts = epoch !== undefined ? new Date(epoch * 1000).toISOString() : fallbackTs;
    const bssid = normalizeBssid(f[1]);
    const subtype = (f[6] ?? "").trim().toLowerCase();
    const sa = normalizeMacAddress(f[7]);
    const isBeaconLike = subtype === "0x08" || subtype === "0x05" || subtype === "8" || subtype === "5";

    if (bssid && isBeaconLike) {
      const { ssid, hidden } = sanitizeSsid(f[2]);
      const channel = num(f[3]);
      const frequencyMhz = num(f[4]);
      const signalDbm = num(f[5]);
      const akmText = (f[9] ?? "").trim();
      const cipherText = (f[10] ?? "").trim();
      const pmfText = (f[11] ?? "").trim().toLowerCase();
      const privacyBit = (f[12] ?? "").trim();
      const sec = normalizeWirelessSecurity({
        versions: akmText || cipherText ? ["WPA2"] : [],
        akms: akmText ? akmText.split(/[,\s]+/).filter(Boolean) : [],
        // Privacy bit set with NO RSN evidence = WEP (pre-RSN security);
        // privacy bit clear = OPEN (§31/§33/§34 evidence rules).
        ciphers: cipherText ? cipherText.split(/[,\s]+/).filter(Boolean)
          : privacyBit === "1" ? ["WEP104"] : [],
        ...(privacyBit === "0" ? { privacyText: "OPEN" } : {}),
        ...(pmfText === "required" || pmfText === "capable" ? { pmf: pmfText } : pmfText ? { pmf: "not-observed" } : {}),
      });
      const vendor = inferVendorFromBssid(bssid);
      const ap = buildAp({
        bssid, ssid, ssidHidden: hidden,
        ...(vendor ? { vendor } : {}),
        ...(channel !== undefined ? { channel } : {}),
        ...(frequencyMhz !== undefined ? { frequencyMhz } : {}),
        securityMode: sec.mode,
        ...(sec.encryption ? { encryption: sec.encryption } : {}),
        ...(sec.authentication ? { authentication: sec.authentication } : {}),
        pmf: sec.pmf, wpsAdvertised: sec.wpsAdvertised,
        ...(signalDbm !== undefined ? { signalDbm } : {}),
        firstSeen: ts, lastSeen: ts, source: ctx.toolSlug,
      });
      const prev = aps.get(bssid);
      if (!prev) aps.set(bssid, ap);
      else aps.set(bssid, { ...ap, firstSeen: prev.firstSeen < ts ? prev.firstSeen : ts });
      observations.push({
        timestamp: ts, sensorRef: ctx.sensorRef,
        ...(channel !== undefined ? { channel } : {}),
        bssid, ssid, securityMode: sec.mode,
        ...(signalDbm !== undefined ? { signalDbm } : {}),
        source: ctx.toolSlug,
      });
      continue;
    }

    if ((subtype === "0x0c" || subtype === "12") && epoch !== undefined) {
      const key = bssid ?? sa ?? "unknown";
      const arr = deauthWindows.get(key) ?? [];
      arr.push(epoch);
      deauthWindows.set(key, arr);
      continue;
    }
    if ((subtype === "0x0a" || subtype === "10") && epoch !== undefined) {
      const key = bssid ?? sa ?? "unknown";
      const arr = disassocWindows.get(key) ?? [];
      arr.push(epoch);
      disassocWindows.set(key, arr);
      continue;
    }

    // Data frames (type 2, subtypes 0x20-0x2f in tshark hex notation):
    // transmitter is a station observation — pseudonymized (§9).
    if (sa && bssid && sa !== bssid && /^0x2[0-9a-f]$/.test(subtype)) {
      const fp = pseudonymizeStationAddress(sa, ctx.workspaceKey);
      const prev = stationMap.get(fp);
      const signalDbm = num(f[5]);
      stationMap.set(fp, {
        addressFingerprint: fp, associatedBssid: bssid,
        firstSeen: prev?.firstSeen ?? ts, lastSeen: ts,
        ...(signalDbm !== undefined ? { signalDbm } : {}),
        source: ctx.toolSlug,
      });
    }
  }

  const events: NormalizedWirelessSecurityEvent[] = [];
  const burstEvents = (windows: Map<string, number[]>, type: "DEAUTH_ACTIVITY" | "DISASSOCIATION_ACTIVITY") => {
    for (const [key, epochs] of windows) {
      const sorted = [...epochs].sort((a, b) => a - b);
      let burst = 0;
      let start = 0;
      for (let i = 0; i < sorted.length; i += 1) {
        while (sorted[i]! - sorted[start]! > 60) start += 1;
        burst = Math.max(burst, i - start + 1);
      }
      if (burst >= DEAUTH_BURST_THRESHOLD) {
        events.push({
          type,
          timestamp: new Date(sorted[0]! * 1000).toISOString(),
          ...(normalizeBssid(key) ? { bssid: normalizeBssid(key) } : {}),
          confidence: burst >= DEAUTH_BURST_THRESHOLD * 3 ? "HIGH" : "MEDIUM",
          evidenceSummary: `${burst} ${type === "DEAUTH_ACTIVITY" ? "deauthentication" : "disassociation"} frames within a 60s window (passive observation only — no frames transmitted)`,
          source: ctx.toolSlug,
        });
      }
    }
  };
  burstEvents(deauthWindows, "DEAUTH_ACTIVITY");
  burstEvents(disassocWindows, "DISASSOCIATION_ACTIVITY");

  const apList = [...aps.values()];
  return finalize({
    accessPoints: apList, stations: [...stationMap.values()], observations,
    channelObservations: channelObservations(apList, ctx.toolSlug),
    securityEvents: events, authenticationMaterialCount: 0, framesProcessed: frames,
  }, ctx.toolSlug);
}

// ── hcxtools — hcxpcapngtool summary (§23) ─────────────────────────

/**
 * hcxpcapngtool session-summary parser. Extracts capture METADATA
 * (counts, AP identities where the summary lists them). Hash-material
 * lines (hashcat-format `WPA*...` records the tool can emit in other
 * modes) are NEVER parsed into the model — they increment the
 * authentication-material counter and are dropped (§67).
 */
export function parseHcxPcapngToolSummary(text: string, ctx: WirelessParserContext): ParsedWireless {
  if (typeof text !== "string" || text.length === 0) return emptyParsedWireless({ parserFailures: 1 });
  const fallbackTs = ctx.observedAt ?? new Date().toISOString();
  let authMaterial = 0;
  const aps = new Map<string, NormalizedWirelessAccessPoint>();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (/^WPA\*|^PKMID\*|\*[0-9a-f]{32,}\*/i.test(trimmed) || /^\$krb5/.test(trimmed)) {
      authMaterial += 1; // counted, never retained (§67)
      continue;
    }
    const m = /^([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s{2,}(.+)$/.exec(trimmed);
    if (m) {
      const bssid = normalizeBssid(m[1]);
      if (!bssid) continue;
      const { ssid, hidden } = sanitizeSsid(m[2]);
      aps.set(bssid, buildAp({
        bssid, ssid, ssidHidden: hidden, securityMode: "UNKNOWN",
        firstSeen: fallbackTs, lastSeen: fallbackTs, source: ctx.toolSlug,
      }));
    }
  }
  const apList = [...aps.values()];
  return finalize({
    accessPoints: apList, stations: [], observations: apList.map((ap) => ({
      timestamp: ap.lastSeen, sensorRef: ctx.sensorRef, bssid: ap.bssid, ssid: ap.ssid,
      securityMode: ap.securityMode, source: ctx.toolSlug,
    })),
    channelObservations: [], securityEvents: [], authenticationMaterialCount: authMaterial, framesProcessed: 0,
  }, ctx.toolSlug);
}

// ── Aircrack-ng capture info (§19/§20) ─────────────────────────────

/**
 * aircrack-ng OFFLINE capture-inspection parser. Running the tool
 * against an approved capture artifact (no key material requested)
 * prints a network table (BSSID / ESSID / Encryption). That table is
 * ALL this parser reads. Handshake mentions increment the
 * authentication-material counter — the material is metadata only
 * (§67); cracking modes are refused by AircrackPolicy before any
 * plan exists (§20).
 */
export function parseAircrackCaptureInfo(text: string, ctx: WirelessParserContext): ParsedWireless {
  if (typeof text !== "string" || text.length === 0) return emptyParsedWireless({ parserFailures: 1 });
  const fallbackTs = ctx.observedAt ?? new Date().toISOString();
  let authMaterial = 0;
  const aps = new Map<string, NormalizedWirelessAccessPoint>();
  for (const line of text.split(/\r?\n/)) {
    if (/handshake/i.test(line)) authMaterial += 1;
    const m = /^\s*\d+\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s{2,}(.*?)\s{2,}(\S.*?)\s*$/.exec(line);
    if (!m) continue;
    const bssid = normalizeBssid(m[1]);
    if (!bssid) continue;
    const { ssid, hidden } = sanitizeSsid(m[2]);
    const sec = normalizeWirelessSecurity(securityEvidenceFromPrivacyText(m[3]));
    const vendor = inferVendorFromBssid(bssid);
    aps.set(bssid, buildAp({
      bssid, ssid, ssidHidden: hidden,
      ...(vendor ? { vendor } : {}),
      securityMode: sec.mode,
      ...(sec.encryption ? { encryption: sec.encryption } : {}),
      ...(sec.authentication ? { authentication: sec.authentication } : {}),
      pmf: sec.pmf, wpsAdvertised: sec.wpsAdvertised,
      firstSeen: fallbackTs, lastSeen: fallbackTs, source: ctx.toolSlug,
    }));
  }
  const apList = [...aps.values()];
  return finalize({
    accessPoints: apList, stations: [], observations: apList.map((ap) => ({
      timestamp: ap.lastSeen, sensorRef: ctx.sensorRef, bssid: ap.bssid, ssid: ap.ssid,
      securityMode: ap.securityMode, source: ctx.toolSlug,
    })),
    channelObservations: channelObservations(apList, ctx.toolSlug),
    securityEvents: [], authenticationMaterialCount: authMaterial, framesProcessed: 0,
  }, ctx.toolSlug);
}

// ── Multi-source merge (§54) ────────────────────────────────────────

/** §54: multi-sensor deduplication — observations of the same BSSID
 *  from any number of sensors merge onto ONE canonical AP (latest
 *  security evidence wins; earliest firstSeen is kept); observations
 *  and stations are unioned, stations by fingerprint. */
export function mergeWirelessData(parts: NormalizedWirelessData[]): NormalizedWirelessData {
  const aps = new Map<string, NormalizedWirelessAccessPoint>();
  const stations = new Map<string, NormalizedWirelessStation>();
  const observations: NormalizedWirelessObservation[] = [];
  const events: NormalizedWirelessSecurityEvent[] = [];
  let authMaterial = 0;
  let frames = 0;
  for (const part of parts) {
    for (const ap of part.accessPoints) {
      const prev = aps.get(ap.bssid);
      if (!prev) { aps.set(ap.bssid, ap); continue; }
      const fresher = ap.lastSeen >= prev.lastSeen ? ap : prev;
      aps.set(ap.bssid, {
        ...fresher,
        firstSeen: prev.firstSeen < ap.firstSeen ? prev.firstSeen : ap.firstSeen,
        ssid: prev.ssidHidden && !ap.ssidHidden ? ap.ssid : fresher.ssid,
        ssidHidden: prev.ssidHidden && ap.ssidHidden,
      });
    }
    for (const st of part.stations) {
      const prev = stations.get(st.addressFingerprint);
      if (!prev) stations.set(st.addressFingerprint, st);
      else stations.set(st.addressFingerprint, { ...st, firstSeen: prev.firstSeen < st.firstSeen ? prev.firstSeen : st.firstSeen });
    }
    observations.push(...part.observations);
    events.push(...part.securityEvents);
    authMaterial += part.authenticationMaterialCount;
    frames += part.framesProcessed;
  }
  const apList = [...aps.values()];
  return {
    accessPoints: apList,
    stations: [...stations.values()],
    observations,
    channelObservations: channelObservations(apList, "merged"),
    securityEvents: events,
    authenticationMaterialCount: authMaterial,
    framesProcessed: frames,
    source: "merged",
  };
}

export function emptyWirelessData(source = "none"): NormalizedWirelessData {
  return {
    accessPoints: [], stations: [], observations: [], channelObservations: [],
    securityEvents: [], authenticationMaterialCount: 0, framesProcessed: 0, source,
  };
}
