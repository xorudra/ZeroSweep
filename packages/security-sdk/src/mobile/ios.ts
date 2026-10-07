/**
 * Prompt 17 — iOS static analysis (§37–§41): Info.plist, entitlements,
 * URL schemes, permission usage descriptions, ATS configuration,
 * embedded frameworks and signing/provisioning metadata.
 *
 * Presence is inventory, never a vulnerability (§38): an entitlement
 * or URL scheme becomes a finding only with corroborating evidence
 * and policy. Mach-O binaries are NEVER executed (§41) — binary
 * metadata here is descriptive only. Binary (bplist) plists are not
 * decoded by this build; the intake reports that honestly instead of
 * guessing.
 */
import type { NormalizedMobileData } from "../findings/finding.types";
import { parseMobileXml, type XmlElement } from "./manifest";
import { mobRec, sanitizeMobileText } from "./sanitize";

/** Convert a plist <dict>/<array> element tree into plain data. */
export function plistToData(el: XmlElement): unknown {
  if (el.name === "dict") {
    const out: Record<string, unknown> = {};
    for (let i = 0; i + 1 < el.children.length; i += 2) {
      const key = el.children[i];
      if (key?.name !== "key") continue;
      out[sanitizeMobileText(key.text, 256)] = plistToData(el.children[i + 1]!);
    }
    return out;
  }
  if (el.name === "array") return el.children.map((c) => plistToData(c));
  if (el.name === "string") return sanitizeMobileText(el.text, 4096);
  if (el.name === "integer" || el.name === "real") return Number(el.text) || 0;
  if (el.name === "true") return true;
  if (el.name === "false") return false;
  if (el.name === "date") return sanitizeMobileText(el.text, 64);
  if (el.name === "data") return `[base64 data ${el.text.length} chars — content not decoded]`;
  return undefined;
}

export function parseInfoPlist(xml: string): { data?: Record<string, unknown>; error?: string } {
  if (typeof xml !== "string" || xml.length === 0) return { error: "empty plist" };
  // Binary plists start with "bplist00" — not decoded in this build.
  if (xml.startsWith("bplist")) return { error: "binary plist (bplist) is not decoded by this build — supply the XML plist form" };
  const parsed = parseMobileXml(xml);
  if ("error" in parsed) return { error: parsed.error };
  if (parsed.root.name !== "plist") return { error: "root element is not <plist>" };
  const dict = parsed.root.children.find((c) => c.name === "dict");
  if (!dict) return { error: "plist has no <dict>" };
  return { data: mobRec(plistToData(dict)) };
}

export interface IosAppAnalysis {
  data: NormalizedMobileData;
  ats?: {
    allowsArbitraryLoads: boolean;
    exceptionDomains: { domain: string; allowsInsecureHttp: boolean; includesSubdomains: boolean }[];
  };
  permissionDescriptions: { key: string; description: string }[];
}

/**
 * Analyze an iOS app from its Info.plist + entitlements record +
 * embedded-framework inventory (§37–§41). All inputs are extracted
 * artifacts — nothing is executed.
 */
export function analyzeIosApp(input: {
  infoPlistXml?: string;
  infoPlist?: Record<string, unknown>;
  entitlements?: Record<string, unknown>;
  embeddedFrameworks?: string[];
  provisioning?: Record<string, unknown>;
  source?: string;
}): { analysis?: IosAppAnalysis; error?: string } {
  const source = input.source ?? "ios-analyzer";
  let plist: Record<string, unknown> = input.infoPlist ?? {};
  if (input.infoPlistXml) {
    const parsed = parseInfoPlist(input.infoPlistXml);
    if (parsed.error) return { error: parsed.error };
    plist = parsed.data ?? {};
  }

  const posture: Record<string, unknown> = {};
  const deepLinks: NormalizedMobileData["deepLinks"] = [];
  const permissionDescriptions: { key: string; description: string }[] = [];

  // URL schemes (§38): inventoried — presence is not a vulnerability.
  const urlTypes = Array.isArray(plist.CFBundleURLTypes) ? plist.CFBundleURLTypes : [];
  for (const entry of urlTypes) {
    const rec = mobRec(entry);
    const schemes = Array.isArray(rec.CFBundleURLSchemes) ? rec.CFBundleURLSchemes : [];
    for (const scheme of schemes) {
      if (typeof scheme === "string") deepLinks.push({ scheme: sanitizeMobileText(scheme, 128), autoVerify: false, source });
    }
  }
  // Universal links are declared via entitlements (associated domains).
  const entitlements = input.entitlements ?? {};
  const assocDomains = Array.isArray(entitlements["com.apple.developer.associated-domains"])
    ? (entitlements["com.apple.developer.associated-domains"] as unknown[])
    : [];
  const universalLinkDomains: string[] = [];
  for (const d of assocDomains) {
    if (typeof d === "string" && d.startsWith("applinks:")) universalLinkDomains.push(sanitizeMobileText(d.slice("applinks:".length), 253));
  }
  if (universalLinkDomains.length > 0) posture.universalLinkDomains = universalLinkDomains;
  const entitlementKeys = Object.keys(entitlements);
  if (entitlementKeys.length > 0) posture.entitlementKeys = entitlementKeys.map((k) => sanitizeMobileText(k, 256));

  // Permission usage descriptions (§37): keys ending in
  // UsageDescription — inventoried WITH their description presence.
  for (const [key, value] of Object.entries(plist)) {
    if (key.endsWith("UsageDescription")) {
      permissionDescriptions.push({
        key: sanitizeMobileText(key, 128),
        description: typeof value === "string" ? sanitizeMobileText(value, 512) : "",
      });
    }
  }

  // ATS (§39): broad exceptions are flagged by policy in the analysis
  // engine; here they are inventoried precisely.
  let ats: IosAppAnalysis["ats"];
  const atsRec = mobRec(plist.NSAppTransportSecurity);
  if (Object.keys(atsRec).length > 0) {
    const exceptions: { domain: string; allowsInsecureHttp: boolean; includesSubdomains: boolean }[] = [];
    const excRec = mobRec(atsRec.NSExceptionDomains);
    for (const [domain, cfg] of Object.entries(excRec)) {
      const c = mobRec(cfg);
      exceptions.push({
        domain: sanitizeMobileText(domain, 253),
        allowsInsecureHttp: c.NSExceptionAllowsInsecureHTTPLoads === true,
        includesSubdomains: c.NSIncludesSubdomains === true,
      });
    }
    ats = {
      allowsArbitraryLoads: atsRec.NSAllowsArbitraryLoads === true,
      exceptionDomains: exceptions,
    };
    posture.ats = { allowsArbitraryLoads: ats.allowsArbitraryLoads, exceptionCount: exceptions.length };
    posture.atsExceptions = exceptions;
  }

  const frameworks = (input.embeddedFrameworks ?? []).map((f) => sanitizeMobileText(f, 256)).filter(Boolean);
  if (frameworks.length > 0) posture.embeddedFrameworks = frameworks;

  // Provisioning metadata (§40): descriptive only — a "get-task-allow"
  // development profile is a fact the engine weighs, never a claim
  // from naming alone (§32 discipline).
  if (input.provisioning) {
    const prov = input.provisioning;
    posture.provisioning = {
      ...(typeof prov.name === "string" ? { name: sanitizeMobileText(prov.name, 256) } : {}),
      ...(typeof prov.getTaskAllow === "boolean" ? { getTaskAllow: prov.getTaskAllow } : {}),
      ...(typeof prov.expirationDate === "string" ? { expirationDate: sanitizeMobileText(prov.expirationDate, 64) } : {}),
    };
  }

  const data: NormalizedMobileData = {
    applicationRef: typeof plist.CFBundleIdentifier === "string" ? sanitizeMobileText(plist.CFBundleIdentifier, 256) : undefined,
    platform: "IOS",
    ...(typeof plist.CFBundleShortVersionString === "string" ? { versionName: sanitizeMobileText(plist.CFBundleShortVersionString, 64) } : {}),
    ...(typeof plist.MinimumOSVersion === "string" ? { minOsVersion: sanitizeMobileText(plist.MinimumOSVersion, 32) } : {}),
    permissions: permissionDescriptions.map((p) => ({
      name: p.key, classification: "UNKNOWN" as const, source,
    })),
    components: [], deepLinks, endpoints: [], nativeLibraries: [], signing: [], sdkInventory: [],
    posture,
    source,
  };
  return { analysis: { data, ...(ats ? { ats } : {}), permissionDescriptions } };
}
