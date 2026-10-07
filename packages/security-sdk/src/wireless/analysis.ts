/**
 * Prompt 19 — wireless posture analysis (§32–§60).
 *
 * Deterministic analysis over NORMALIZED observations — no AI, no
 * invention, no transmission. Every finding traces to observed
 * evidence: a security mode seen in a beacon, a profile mismatch, a
 * drift between two inventories. Classifications stay honest:
 *  - an unknown AP is UNKNOWN, never "malicious" (§44);
 *  - an evil-twin SUSPECT is SUSPICIOUS, never "confirmed" (§45);
 *  - drift is a configuration fact, not an accusation (§56);
 *  - compliance mappings are organizational policy, never a formal
 *    certification claim (§58).
 */
import type {
  NormalizedFinding, NormalizedWirelessAccessPoint, NormalizedWirelessData,
  NormalizedWirelessSecurityEvent,
} from "../findings/finding.types";
import { wirelessSha256Hex } from "./sanitize";
import { isSecurityDowngrade } from "./security";
import {
  DEFAULT_WIRELESS_GATE_RULES, type ApprovedWirelessProfileShape, type RogueClassification,
  type WirelessDriftKind, type WirelessGateRules,
} from "./types";

export interface WirelessAnalysisContext {
  environmentId: string;
  /** CORPORATE | GUEST | LAB | OFFICE | PUBLIC | UNKNOWN — drives
   *  contextual risk (§34) and gate PMF requirements (§60). */
  environmentKind: string;
  approvedProfiles: ApprovedWirelessProfileShape[];
  gateRules?: WirelessGateRules;
  sourceTool?: string;
}

/** §53: canonical wireless fingerprint — environment + BSSID + rule
 *  + security mode + finding class. NEVER the SSID alone (§5/§53). */
export function wirelessFindingFingerprint(input: {
  environmentId: string; bssid: string; rule: string; securityMode: string; findingClass: string;
}): string {
  return wirelessSha256Hex(["wireless", input.environmentId, input.bssid.toLowerCase(), input.rule, input.securityMode, input.findingClass].join("|"));
}

function finding(
  ctx: WirelessAnalysisContext, ap: NormalizedWirelessAccessPoint, rule: string,
  type: NormalizedFinding["wirelessFindingType"], severity: NormalizedFinding["severity"],
  title: string, description: string, remediation: string,
  rogue?: RogueClassification,
): NormalizedFinding {
  const fingerprint = wirelessFindingFingerprint({
    environmentId: ctx.environmentId, bssid: ap.bssid, rule, securityMode: ap.securityMode, findingClass: type ?? "",
  });
  return {
    title, description, severity, confidence: 0.9,
    host: ap.bssid,
    evidence: `BSSID ${ap.bssid} · SSID "${ap.ssid || "(hidden)"}" · mode ${ap.securityMode}`
      + `${ap.encryption ? ` · cipher ${ap.encryption}` : ""}${ap.authentication ? ` · auth ${ap.authentication}` : ""}`
      + ` · channel ${ap.channel ?? "?"} · PMF ${ap.pmf} · WPS ${ap.wpsAdvertised ? "advertised" : "not observed"}`,
    remediation,
    references: [],
    sourceTool: ctx.sourceTool ?? "wireless-posture",
    sourceFingerprint: fingerprint,
    wirelessEnvironmentId: ctx.environmentId,
    wirelessBssid: ap.bssid,
    wirelessFindingType: type,
    wirelessFingerprint: fingerprint,
    ...(rogue ? { wirelessRogueClassification: rogue } : {}),
  };
}

// ── Encryption / authentication posture (§32–§39) ──────────────────

export function analyzeWirelessEncryption(
  aps: NormalizedWirelessAccessPoint[], ctx: WirelessAnalysisContext,
): NormalizedFinding[] {
  const out: NormalizedFinding[] = [];
  const rules = ctx.gateRules ?? DEFAULT_WIRELESS_GATE_RULES;
  for (const ap of aps) {
    // §33: evidence-backed WEP is a high-priority posture finding.
    // Key recovery is never attempted.
    if (ap.securityMode === "WEP") {
      out.push(finding(ctx, ap, "WIRELESS_WEP_IN_USE", "WIRELESS_ENCRYPTION_FINDING", "HIGH",
        `WEP encryption in use on ${ap.bssid}`,
        "The access point advertises WEP, a broken legacy encryption scheme whose key can be recovered trivially by passive observation. This is an evidence-backed posture finding; no key recovery was attempted (§33).",
        "Disable WEP and migrate this SSID to WPA2/WPA3 or 802.1X Enterprise."));
    }
    // §34: open networks are inventory + a CONTEXTUAL finding — guest
    // isolation and intended use determine the risk, not the label.
    if (ap.securityMode === "OPEN") {
      const guestContext = ctx.environmentKind === "GUEST" || ctx.environmentKind === "PUBLIC";
      out.push(finding(ctx, ap, "WIRELESS_OPEN_NETWORK", "WIRELESS_ENCRYPTION_FINDING", guestContext ? "LOW" : "MEDIUM",
        `Open (unencrypted) wireless network ${ap.bssid}`,
        guestContext
          ? "An open network was observed in a guest/public environment. Risk depends on guest isolation and segmentation, which must be verified out-of-band (§34)."
          : "An open network was observed in a non-guest environment: traffic is unencrypted and any station may associate. Risk depends on intended use and segmentation (§34).",
        "Encrypt the network (WPA2/WPA3 or OWE for open-access use cases) or document it as an intentionally isolated guest network."));
    }
    // Legacy WPA/TKIP (§32).
    if (ap.securityMode === "WPA" || (ap.encryption ?? "").includes("TKIP")) {
      out.push(finding(ctx, ap, "WIRELESS_LEGACY_WPA_TKIP", "WIRELESS_ENCRYPTION_FINDING", "MEDIUM",
        `Legacy WPA/TKIP configuration on ${ap.bssid}`,
        "The access point offers WPA (v1) and/or the TKIP cipher, both deprecated with known weaknesses.",
        "Move to WPA2-CCMP at minimum; prefer WPA3-SAE or Enterprise."));
    }
    // §36: transition mode is a policy decision, surfaced as a finding.
    if (ap.securityMode === "TRANSITION") {
      out.push(finding(ctx, ap, "WIRELESS_TRANSITION_MODE", "WIRELESS_CONFIGURATION_FINDING", "LOW",
        `WPA2/WPA3 transition mode on ${ap.bssid}`,
        "The access point offers both WPA2 and WPA3 AKMs (transition mode). This is acceptable only where organizational policy permits it (§36); transition mode weakens WPA3 downgrade resistance.",
        "Confirm transition mode is policy-approved, or complete the WPA3 migration."));
    }
    // §38/§60: PMF posture on environments whose policy requires it.
    if (rules.requiredPmfEnvironments.includes(ctx.environmentKind)
      && ap.pmf !== "REQUIRED" && ap.securityMode !== "OPEN" && ap.securityMode !== "WEP") {
      out.push(finding(ctx, ap, "WIRELESS_PMF_NOT_REQUIRED", "WIRELESS_CONFIGURATION_FINDING", "MEDIUM",
        `Protected Management Frames not required on ${ap.bssid}`,
        `PMF state is ${ap.pmf} in a ${ctx.environmentKind} environment whose policy requires PMF (§38/§60). Without PMF, deauthentication spoofing against clients is easier.`,
        "Set PMF to REQUIRED for this SSID where client support permits."));
    }
    // §39: WPS advertisement is posture metadata — PIN attacks are
    // never attempted.
    if (ap.wpsAdvertised) {
      out.push(finding(ctx, ap, "WIRELESS_WPS_ADVERTISED", "WIRELESS_AUTH_FINDING", "MEDIUM",
        `WPS advertised on ${ap.bssid}`,
        "The access point advertises Wi-Fi Protected Setup. WPS PIN mode has known design weaknesses; this finding is from passively observed advertisement only — no PIN attack was attempted (§39).",
        "Disable WPS, or restrict it to push-button mode per policy."));
    }
  }
  return out;
}

// ── Rogue AP analysis (§42–§45) ─────────────────────────────────────

export interface RogueAnalysisResult {
  classifications: { bssid: string; classification: RogueClassification; reasons: string[] }[];
  findings: NormalizedFinding[];
  events: NormalizedWirelessSecurityEvent[];
}

export function analyzeRogueAccessPoints(
  aps: NormalizedWirelessAccessPoint[], ctx: WirelessAnalysisContext,
): RogueAnalysisResult {
  const classifications: RogueAnalysisResult["classifications"] = [];
  const findings: NormalizedFinding[] = [];
  const events: NormalizedWirelessSecurityEvent[] = [];
  const profiles = ctx.approvedProfiles;

  for (const ap of aps) {
    const bySsid = profiles.filter((p) => p.ssid === ap.ssid && ap.ssid !== "");
    const byBssid = profiles.find((p) => p.bssid && p.bssid.toLowerCase() === ap.bssid.toLowerCase());
    if (byBssid) {
      // Known BSSID: a weaker posture than the approved profile is a
      // policy violation ON APPROVED infrastructure (§44).
      if (isSecurityDowngrade(byBssid.securityMode, ap.securityMode) || ap.securityMode === "WEP" || ap.securityMode === "OPEN") {
        classifications.push({ bssid: ap.bssid, classification: "POLICY_VIOLATION", reasons: [`approved BSSID observed with posture ${ap.securityMode}, profile expects ${byBssid.securityMode}`] });
        findings.push(finding(ctx, ap, "WIRELESS_APPROVED_AP_WEAKENED", "WIRELESS_ROGUE_AP_FINDING", "HIGH",
          `Approved AP ${ap.bssid} observed below its approved posture`,
          `The approved profile expects ${byBssid.securityMode} but the AP was observed as ${ap.securityMode}.`,
          "Restore the approved security configuration or update the approved profile through change control.",
          "POLICY_VIOLATION"));
      } else {
        classifications.push({ bssid: ap.bssid, classification: "APPROVED", reasons: ["BSSID matches an approved profile with conforming posture"] });
      }
      continue;
    }
    if (bySsid.length > 0) {
      // §45 evil-twin INDICATORS: same SSID, unexpected BSSID, and a
      // weaker security mode / unexpected vendor or channel. The
      // classification is SUSPICIOUS — never a confirmed evil twin.
      const expected = bySsid[0]!;
      const weaker = isSecurityDowngrade(expected.securityMode, ap.securityMode);
      const channelUnexpected = expected.allowedChannels.length > 0 && ap.channel !== undefined && !expected.allowedChannels.includes(ap.channel);
      if (weaker || channelUnexpected) {
        const reasons = [
          "SSID matches an approved profile but the BSSID is not approved",
          ...(weaker ? [`security mode ${ap.securityMode} is weaker than approved ${expected.securityMode}`] : []),
          ...(channelUnexpected ? [`channel ${ap.channel} is outside the approved channel set`] : []),
        ];
        classifications.push({ bssid: ap.bssid, classification: "SUSPICIOUS", reasons });
        findings.push(finding(ctx, ap, "WIRELESS_ROGUE_AP_SUSPECTED", "WIRELESS_ROGUE_AP_FINDING", "HIGH",
          `Suspected rogue AP advertising "${ap.ssid}" (${ap.bssid})`,
          `Defensive indicators (§45): ${reasons.join("; ")}. Classified SUSPICIOUS — this is NOT a confirmed evil twin; investigation is required. No action was taken against the AP.`,
          "Investigate the device physically and via the WLAN controller; if unauthorized, follow the rogue-AP containment process.",
          "SUSPICIOUS"));
        events.push({
          type: "ROGUE_AP_SUSPECTED", timestamp: ap.lastSeen, bssid: ap.bssid, confidence: weaker ? "MEDIUM" : "LOW",
          evidenceSummary: reasons.join("; "), source: ctx.sourceTool ?? "wireless-posture",
        });
      } else {
        classifications.push({ bssid: ap.bssid, classification: "UNKNOWN", reasons: ["SSID matches an approved profile but the BSSID is not in the approved inventory — may be a legitimate unregistered AP"] });
        findings.push(finding(ctx, ap, "WIRELESS_UNKNOWN_AP_ON_APPROVED_SSID", "WIRELESS_ROGUE_AP_FINDING", "MEDIUM",
          `Unregistered AP advertising approved SSID "${ap.ssid}" (${ap.bssid})`,
          "The BSSID is not in the approved inventory. It is classified UNKNOWN (§44) — not malicious without evidence — but corporate SSIDs should only be served by approved APs.",
          "Register the AP if legitimate, or investigate if not.",
          "UNKNOWN"));
        events.push({
          type: "NEW_UNKNOWN_AP", timestamp: ap.lastSeen, bssid: ap.bssid, confidence: "MEDIUM",
          evidenceSummary: `Unregistered BSSID advertising approved SSID "${ap.ssid}"`, source: ctx.sourceTool ?? "wireless-posture",
        });
      }
      continue;
    }
    classifications.push({ bssid: ap.bssid, classification: "UNKNOWN", reasons: ["not in the approved inventory — environmental metadata only (§63)"] });
  }

  // §48/§55: approved APs that were expected but not observed.
  const observed = new Set(aps.map((a) => a.bssid.toLowerCase()));
  for (const p of profiles) {
    if (p.bssid && !observed.has(p.bssid.toLowerCase())) {
      events.push({
        type: "APPROVED_AP_MISSING", timestamp: new Date().toISOString(), bssid: p.bssid, confidence: "LOW",
        evidenceSummary: `Approved AP ${p.bssid} ("${p.ssid}") was not observed in this session`, source: ctx.sourceTool ?? "wireless-posture",
      });
    }
  }
  return { classifications, findings, events };
}

// ── Drift (§55/§56) ─────────────────────────────────────────────────

export interface WirelessDriftRecord {
  kind: WirelessDriftKind;
  bssid: string;
  ssid: string;
  field: string;
  fromValue?: string;
  toValue?: string;
  /** A downgrade turns drift into a policy finding (§88). */
  securityDowngrade: boolean;
}

export function detectWirelessDrift(
  previous: NormalizedWirelessAccessPoint[], current: NormalizedWirelessAccessPoint[],
  ctx: WirelessAnalysisContext,
): { drift: WirelessDriftRecord[]; findings: NormalizedFinding[]; events: NormalizedWirelessSecurityEvent[] } {
  const drift: WirelessDriftRecord[] = [];
  const findings: NormalizedFinding[] = [];
  const events: NormalizedWirelessSecurityEvent[] = [];
  const prevByBssid = new Map(previous.map((a) => [a.bssid.toLowerCase(), a]));
  const currByBssid = new Map(current.map((a) => [a.bssid.toLowerCase(), a]));

  for (const ap of current) {
    const prev = prevByBssid.get(ap.bssid.toLowerCase());
    if (!prev) {
      drift.push({ kind: "NEW_AP", bssid: ap.bssid, ssid: ap.ssid, field: "presence", toValue: "observed", securityDowngrade: false });
      continue;
    }
    if (prev.securityMode !== ap.securityMode) {
      const downgrade = isSecurityDowngrade(prev.securityMode, ap.securityMode);
      drift.push({ kind: "ENCRYPTION_CHANGED", bssid: ap.bssid, ssid: ap.ssid, field: "securityMode", fromValue: prev.securityMode, toValue: ap.securityMode, securityDowngrade: downgrade });
      events.push({
        type: "SECURITY_MODE_CHANGED", timestamp: ap.lastSeen, bssid: ap.bssid,
        confidence: downgrade ? "HIGH" : "MEDIUM",
        evidenceSummary: `Security mode changed ${prev.securityMode} → ${ap.securityMode}${downgrade ? " (downgrade)" : ""}`,
        source: ctx.sourceTool ?? "wireless-posture",
      });
      if (downgrade) {
        findings.push(finding(ctx, ap, "WIRELESS_SECURITY_MODE_DOWNGRADE", "WIRELESS_ENCRYPTION_FINDING", "HIGH",
          `Security downgrade on ${ap.bssid}: ${prev.securityMode} → ${ap.securityMode}`,
          "Drift detection (§56/§88): the AP's security mode weakened between observations. Drift alone is not labelled malicious, but a downgrade is a policy finding requiring review.",
          "Restore the previous security mode or document the approved change."));
      }
    }
    if ((prev.authentication ?? "") !== (ap.authentication ?? "")) {
      drift.push({ kind: "AUTHENTICATION_CHANGED", bssid: ap.bssid, ssid: ap.ssid, field: "authentication", fromValue: prev.authentication, toValue: ap.authentication, securityDowngrade: false });
    }
    if (prev.channel !== undefined && ap.channel !== undefined && prev.channel !== ap.channel) {
      const profile = ctx.approvedProfiles.find((p) => p.bssid?.toLowerCase() === ap.bssid.toLowerCase());
      if (profile && profile.allowedChannels.length > 0 && !profile.allowedChannels.includes(ap.channel)) {
        drift.push({ kind: "CHANNEL_POLICY_CHANGED", bssid: ap.bssid, ssid: ap.ssid, field: "channel", fromValue: String(prev.channel), toValue: String(ap.channel), securityDowngrade: false });
      }
    }
  }
  for (const ap of previous) {
    if (!currByBssid.has(ap.bssid.toLowerCase())) {
      drift.push({ kind: "AP_DISAPPEARED", bssid: ap.bssid, ssid: ap.ssid, field: "presence", fromValue: "observed", securityDowngrade: false });
    }
  }
  // §56: same SSID served by entirely different BSSIDs across snapshots.
  const prevSsids = new Map<string, Set<string>>();
  for (const ap of previous) if (ap.ssid) prevSsids.set(ap.ssid, new Set([...(prevSsids.get(ap.ssid) ?? []), ap.bssid.toLowerCase()]));
  for (const ap of current) {
    if (!ap.ssid) continue;
    const before = prevSsids.get(ap.ssid);
    if (before && before.size > 0 && ![...before].some((b) => currByBssid.has(b))) {
      drift.push({ kind: "BSSID_CHANGED", bssid: ap.bssid, ssid: ap.ssid, field: "bssidSet", fromValue: [...before].join(","), toValue: ap.bssid, securityDowngrade: false });
    }
  }
  return { drift, findings, events };
}

// ── Quality gate (§60) ──────────────────────────────────────────────

export interface WirelessGateResult {
  status: "PASSED" | "FAILED";
  failedRules: string[];
  warningRules: string[];
}

export function evaluateWirelessGate(
  aps: NormalizedWirelessAccessPoint[], findings: NormalizedFinding[],
  ctx: WirelessAnalysisContext,
): WirelessGateResult {
  const rules = ctx.gateRules ?? DEFAULT_WIRELESS_GATE_RULES;
  const failed: string[] = [];
  const warnings: string[] = [];
  if (rules.noWep && aps.some((a) => a.securityMode === "WEP")) failed.push("NO_WEP");
  if (rules.noUnauthorizedOpenCorporateSsids && ctx.environmentKind !== "GUEST" && ctx.environmentKind !== "PUBLIC") {
    const openCorporate = aps.some((a) => a.securityMode === "OPEN"
      && ctx.approvedProfiles.some((p) => p.ssid === a.ssid && p.bssid?.toLowerCase() === a.bssid.toLowerCase()));
    if (openCorporate) failed.push("NO_UNAUTHORIZED_OPEN_CORPORATE_SSIDS");
  }
  if (rules.noCriticalRogueApFinding
    && findings.some((f) => f.wirelessFindingType === "WIRELESS_ROGUE_AP_FINDING" && (f.severity === "CRITICAL" || f.severity === "HIGH"))) {
    failed.push("NO_CRITICAL_ROGUE_AP_FINDING");
  }
  if (rules.requiredPmfEnvironments.includes(ctx.environmentKind)
    && aps.some((a) => a.pmf !== "REQUIRED" && a.securityMode !== "OPEN" && a.securityMode !== "WEP")) {
    warnings.push("REQUIRED_PMF");
  }
  for (const mode of rules.prohibitedSecurityModes) {
    if (mode !== "WEP" && aps.some((a) => a.securityMode === mode)) failed.push(`NO_PROHIBITED_MODE_${mode}`);
  }
  if (findings.some((f) => f.wirelessFindingType === "WIRELESS_ROGUE_AP_FINDING" && f.wirelessRogueClassification === "SUSPICIOUS")) {
    warnings.push("ROGUE_AP_SUSPECTED_REVIEW");
  }
  return { status: failed.length > 0 ? "FAILED" : "PASSED", failedRules: failed, warningRules: warnings };
}

// ── Risk factors (§57) ──────────────────────────────────────────────

const MODE_RISK: Record<string, number> = {
  OPEN: 30, WEP: 35, WPA: 20, PERSONAL: 10, WPA2: 8, TRANSITION: 10, WPA3: 4, ENTERPRISE: 2, UNKNOWN: 15,
};

/** §57: deterministic wireless risk context for Risk Engine V2 —
 *  encryption strength, authentication mode, environment, approved
 *  state, PMF, WPS, drift and event confidence as stored factors. */
export function computeWirelessRiskFactors(input: {
  ap: NormalizedWirelessAccessPoint;
  environmentKind: string;
  approved: boolean;
  rogueClassification?: RogueClassification;
  drifted?: boolean;
  eventConfidence?: "LOW" | "MEDIUM" | "HIGH";
}): { score: number; factors: string[] } {
  const factors: string[] = [];
  let score = MODE_RISK[input.ap.securityMode] ?? 10;
  factors.push(`encryption mode ${input.ap.securityMode} (+${MODE_RISK[input.ap.securityMode] ?? 10})`);
  if (input.ap.authentication === "EAP/802.1X") { score -= 2; factors.push("enterprise authentication (−2)"); }
  if (input.ap.pmf === "REQUIRED") { score -= 2; factors.push("PMF required (−2)"); }
  if (input.ap.pmf === "NOT_OBSERVED" && input.ap.securityMode !== "OPEN") { score += 4; factors.push("PMF not observed (+4)"); }
  if (input.ap.wpsAdvertised) { score += 6; factors.push("WPS advertised (+6)"); }
  if (!input.approved) { score += 8; factors.push("AP not in approved inventory (+8)"); }
  if (input.rogueClassification === "SUSPICIOUS") { score += 20; factors.push("rogue classification SUSPICIOUS (+20)"); }
  if (input.rogueClassification === "POLICY_VIOLATION") { score += 15; factors.push("rogue classification POLICY_VIOLATION (+15)"); }
  if (input.environmentKind === "CORPORATE") { score += 5; factors.push("corporate environment (+5)"); }
  if (input.drifted) { score += 5; factors.push("security drift observed (+5)"); }
  if (input.eventConfidence === "HIGH") { score += 6; factors.push("correlated high-confidence event (+6)"); }
  return { score: Math.max(0, Math.min(100, score)), factors };
}

// ── Full posture pass (§32–§60) ─────────────────────────────────────

export interface WirelessPostureResult {
  findings: NormalizedFinding[];
  events: NormalizedWirelessSecurityEvent[];
  classifications: RogueAnalysisResult["classifications"];
  gate: WirelessGateResult;
}

/** One deterministic posture pass over a normalized payload: the
 *  platform stage (WIRELESS_POSTURE_ANALYSIS) and the API both run
 *  exactly this. Adapter findings are NOT re-derived here — posture
 *  findings are platform findings with the §53 fingerprint. */
export function analyzeWirelessPosture(data: NormalizedWirelessData, ctx: WirelessAnalysisContext): WirelessPostureResult {
  const encryption = analyzeWirelessEncryption(data.accessPoints, ctx);
  const rogue = analyzeRogueAccessPoints(data.accessPoints, ctx);
  const byFingerprint = new Map<string, NormalizedFinding>();
  for (const f of [...encryption, ...rogue.findings]) byFingerprint.set(f.wirelessFingerprint ?? f.sourceFingerprint, f);
  const findings = [...byFingerprint.values()];
  const events = [...data.securityEvents, ...rogue.events];
  const gate = evaluateWirelessGate(data.accessPoints, findings, ctx);
  return { findings, events, classifications: rogue.classifications, gate };
}
