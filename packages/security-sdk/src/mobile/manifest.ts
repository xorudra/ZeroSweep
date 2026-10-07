/**
 * Prompt 17 — Android manifest + network security config analysis
 * (§20–§27) over a small hardened XML reader.
 *
 * Manifest XML is hostile content (§107): DOCTYPE/ENTITY declarations
 * are refused outright (XXE), sizes/depth/element counts are capped,
 * and every extracted string passes the mobile sanitizer. Analysis is
 * EVIDENCE-based: an exported component is NOT automatically a
 * vulnerability (§21), a dangerous permission is inventoried, not
 * auto-flagged (§22), and presence alone never becomes a claim.
 */
import type {
  NormalizedMobileComponent, NormalizedMobileData, NormalizedMobileDeepLink,
  NormalizedMobilePermission,
} from "../findings/finding.types";
import { sanitizeMobileText } from "./sanitize";

export interface XmlElement {
  name: string;
  attrs: Record<string, string>;
  children: XmlElement[];
  text: string;
}

const MAX_XML_BYTES = 4 * 1024 * 1024;
const MAX_ELEMENTS = 20000;
const MAX_DEPTH = 64;

/** Parse XML into an element tree, failing closed on hostile shapes. */
export function parseMobileXml(xml: string): { root: XmlElement } | { error: string } {
  if (typeof xml !== "string" || xml.length === 0) return { error: "empty XML" };
  if (Buffer.byteLength(xml, "utf8") > MAX_XML_BYTES) return { error: "XML exceeds the 4MB analysis cap" };
  if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml)) {
    return { error: "DOCTYPE/ENTITY declarations are refused (XXE discipline, §107)" };
  }
  let i = 0;
  let elements = 0;
  const n = xml.length;
  const stack: XmlElement[] = [];
  let root: XmlElement | undefined;
  const fail = (error: string) => ({ error });
  while (i < n) {
    const lt = xml.indexOf("<", i);
    if (lt === -1) break;
    if (stack.length > 0 && lt > i) {
      stack[stack.length - 1]!.text += xml.slice(i, lt);
    }
    if (xml.startsWith("<!--", lt)) {
      const end = xml.indexOf("-->", lt + 4);
      if (end === -1) return fail("unterminated comment");
      i = end + 3;
      continue;
    }
    if (xml.startsWith("<?", lt)) {
      const end = xml.indexOf("?>", lt + 2);
      if (end === -1) return fail("unterminated processing instruction");
      i = end + 2;
      continue;
    }
    if (xml.startsWith("<!", lt)) return fail("markup declarations are refused (§107)");
    const gt = xml.indexOf(">", lt);
    if (gt === -1) return fail("unterminated tag");
    const raw = xml.slice(lt + 1, gt);
    if (raw.startsWith("/")) {
      const name = raw.slice(1).trim();
      const el = stack.pop();
      if (!el || el.name !== name) return fail(`mismatched closing tag </${name}>`);
      if (stack.length === 0) root = el;
      i = gt + 1;
      continue;
    }
    const selfClosing = raw.endsWith("/");
    const body = selfClosing ? raw.slice(0, -1) : raw;
    const spaceIdx = body.search(/\s/);
    const name = (spaceIdx === -1 ? body : body.slice(0, spaceIdx)).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_.:-]*$/.test(name)) return fail(`invalid element name ${JSON.stringify(name.slice(0, 40))}`);
    if (++elements > MAX_ELEMENTS) return fail("element count exceeds the analysis cap");
    if (stack.length + 1 > MAX_DEPTH) return fail("XML nesting exceeds the analysis cap");
    const attrs: Record<string, string> = {};
    const attrSrc = spaceIdx === -1 ? "" : body.slice(spaceIdx + 1);
    const attrRe = /([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*"([^"]*)"|([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*'([^']*)'/g;
    let m: RegExpExecArray | null;
    while ((m = attrRe.exec(attrSrc)) !== null) {
      const key = (m[1] ?? m[3])!;
      const val = decodeEntities((m[2] ?? m[4]) ?? "");
      attrs[key] = sanitizeMobileText(val, 1024);
    }
    const el: XmlElement = { name, attrs, children: [], text: "" };
    if (stack.length > 0) stack[stack.length - 1]!.children.push(el);
    if (selfClosing) {
      if (stack.length === 0) root = el;
    } else {
      stack.push(el);
    }
    i = gt + 1;
  }
  if (stack.length > 0) return fail("unclosed elements remain");
  if (!root) return fail("no root element");
  root.text = root.text.trim();
  return { root };
}

function decodeEntities(s: string): string {
  return s
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'").replace(/&#(\d+);/g, (_m, d: string) => {
      const cp = Number(d);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : "";
    })
    .replace(/&amp;/g, "&");
}

function attr(el: XmlElement, name: string): string | undefined {
  return el.attrs[`android:${name}`] ?? el.attrs[name];
}

function boolAttr(el: XmlElement, name: string): boolean | undefined {
  const v = attr(el, name);
  if (v === undefined) return undefined;
  if (v.toLowerCase() === "true") return true;
  if (v.toLowerCase() === "false") return false;
  return undefined;
}

/** Android permission protection levels (§22). The well-known
 *  dangerous set is versioned platform knowledge; unknown permissions
 *  are CUSTOM/UNKNOWN — inventoried, never auto-flagged. */
const DANGEROUS_PERMISSIONS = new Set([
  "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
  "android.permission.CAMERA", "android.permission.READ_CONTACTS",
  "android.permission.WRITE_CONTACTS", "android.permission.GET_ACCOUNTS",
  "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.ACCESS_MEDIA_LOCATION", "android.permission.RECORD_AUDIO",
  "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
  "android.permission.CALL_PHONE", "android.permission.USE_SIP",
  "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
  "android.permission.ADD_VOICEMAIL", "android.permission.BODY_SENSORS",
  "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
  "android.permission.READ_SMS", "android.permission.RECEIVE_WAP_PUSH",
  "android.permission.RECEIVE_MMS", "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.READ_MEDIA_IMAGES",
  "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_AUDIO",
  "android.permission.POST_NOTIFICATIONS", "android.permission.BLUETOOTH_CONNECT",
  "android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_ADVERTISE",
  "android.permission.NEARBY_WIFI_DEVICES", "android.permission.ACCESS_BACKGROUND_LOCATION",
]);

const SIGNATURE_PERMISSIONS = new Set([
  "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
  "android.permission.BIND_DEVICE_ADMIN", "android.permission.MANAGE_EXTERNAL_STORAGE",
  "android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.WRITE_SETTINGS", "android.permission.BIND_VPN_SERVICE",
]);

export function classifyAndroidPermission(name: string): NormalizedMobilePermission["classification"] {
  if (DANGEROUS_PERMISSIONS.has(name)) return "DANGEROUS";
  if (SIGNATURE_PERMISSIONS.has(name)) return "SIGNATURE";
  if (!name.startsWith("android.permission.")) return "CUSTOM";
  return "NORMAL";
}

export interface AndroidManifestAnalysis {
  data: NormalizedMobileData;
  /** §24: network security config facts (also folded into posture). */
  networkSecurity?: {
    cleartextTrafficPermitted?: boolean;
    domainExceptions: { domain: string; cleartextPermitted: boolean }[];
    pinningDeclared: boolean;
  };
}

/**
 * Analyze an AndroidManifest.xml (text form, as produced by apktool /
 * MobSF / AAPT dumps) plus an optional network-security-config XML
 * (§20–§27). Output is INVENTORY + posture facts; findings are derived
 * by the analysis engine, never here.
 */
export function analyzeAndroidManifest(manifestXml: string, opts: { networkSecurityConfigXml?: string; source?: string } = {}): { analysis?: AndroidManifestAnalysis; error?: string } {
  const source = opts.source ?? "manifest-analyzer";
  const parsed = parseMobileXml(manifestXml);
  if ("error" in parsed) return { error: parsed.error };
  const root = parsed.root;
  if (root.name !== "manifest") return { error: "root element is not <manifest>" };

  const permissions: NormalizedMobilePermission[] = [];
  const components: NormalizedMobileComponent[] = [];
  const deepLinks: NormalizedMobileDeepLink[] = [];
  let minSdk: string | undefined;
  let targetSdk: string | undefined;
  let applicationEl: XmlElement | undefined;

  for (const child of root.children) {
    if (child.name === "uses-permission" || child.name === "uses-permission-sdk-23") {
      const name = attr(child, "name");
      if (name) permissions.push({ name, classification: classifyAndroidPermission(name), source });
    } else if (child.name === "uses-sdk") {
      minSdk = attr(child, "minSdkVersion");
      targetSdk = attr(child, "targetSdkVersion");
    } else if (child.name === "application") {
      applicationEl = child;
    }
  }

  const posture: Record<string, unknown> = {};
  if (applicationEl) {
    const debuggable = boolAttr(applicationEl, "debuggable");
    if (debuggable !== undefined) posture.debuggable = debuggable;
    const allowBackup = boolAttr(applicationEl, "allowBackup");
    if (allowBackup !== undefined) posture.allowBackup = allowBackup;
    const cleartext = boolAttr(applicationEl, "usesCleartextTraffic");
    if (cleartext !== undefined) posture.usesCleartextTraffic = cleartext;
    const nsc = attr(applicationEl, "networkSecurityConfig");
    if (nsc) posture.networkSecurityConfigRef = nsc;

    const kindMap: Record<string, NormalizedMobileComponent["kind"]> = {
      activity: "ACTIVITY", "activity-alias": "ACTIVITY", service: "SERVICE",
      receiver: "RECEIVER", provider: "PROVIDER",
    };
    for (const comp of applicationEl.children) {
      const kind = kindMap[comp.name];
      if (!kind) continue;
      const name = attr(comp, "name") ?? "(unnamed)";
      const intentFilters = comp.children.filter((c) => c.name === "intent-filter");
      const hasIntentFilter = intentFilters.length > 0;
      const exportedAttr = boolAttr(comp, "exported");
      // Android 12+: exported must be explicit when intent filters
      // exist — absence is a posture fact, recorded as-is.
      const exported = exportedAttr ?? (kind === "PROVIDER" ? false : hasIntentFilter);
      const actions: string[] = [];
      for (const filter of intentFilters) {
        for (const a of filter.children) {
          if (a.name === "action") {
            const an = attr(a, "name");
            if (an) actions.push(an);
          }
          if (a.name === "data") {
            const scheme = attr(a, "scheme");
            if (scheme) {
              deepLinks.push({
                scheme,
                ...(attr(a, "host") ? { host: attr(a, "host") } : {}),
                ...(attr(a, "pathPrefix") ?? attr(a, "path") ? { pathPrefix: attr(a, "pathPrefix") ?? attr(a, "path") } : {}),
                autoVerify: actions.includes("android.intent.action.VIEW") && intentFilters.some((f) =>
                  f.children.some((c) => c.name === "category" && attr(c, "name") === "android.intent.category.BROWSABLE")),
                source,
              });
            }
          }
        }
      }
      components.push({
        kind, name, exported,
        ...(attr(comp, "permission") ? { permission: attr(comp, "permission") } : {}),
        intentActions: [...new Set(actions)],
        source,
      });
      if (kind === "PROVIDER") {
        const grant = boolAttr(comp, "grantUriPermissions");
        if (grant !== undefined) {
          const list = (posture.providerGrantUriPermissions as string[] | undefined) ?? [];
          if (grant) list.push(name);
          posture.providerGrantUriPermissions = list;
        }
      }
    }
  }

  // Network security config (§24).
  let networkSecurity: AndroidManifestAnalysis["networkSecurity"];
  if (opts.networkSecurityConfigXml) {
    const nscParsed = parseMobileXml(opts.networkSecurityConfigXml);
    if (!("error" in nscParsed) && nscParsed.root.name === "network-security-config") {
      const domainExceptions: { domain: string; cleartextPermitted: boolean }[] = [];
      let baseCleartext: boolean | undefined;
      let pinningDeclared = false;
      for (const section of nscParsed.root.children) {
        if (section.name === "base-config") {
          baseCleartext = boolAttr(section, "cleartextTrafficPermitted");
          if (section.children.some((c) => c.name === "trust-anchors")) {
            // trust anchors alone do not declare pinning; pins live in pin-set.
          }
        }
        if (section.name === "domain-config") {
          const cleartext = boolAttr(section, "cleartextTrafficPermitted") ?? false;
          for (const d of section.children) {
            if (d.name === "domain") domainExceptions.push({ domain: sanitizeMobileText(d.text, 253), cleartextPermitted: cleartext });
            if (d.name === "pin-set") pinningDeclared = true;
          }
        }
        if (section.children.some((c) => c.name === "pin-set")) pinningDeclared = true;
      }
      networkSecurity = {
        ...(baseCleartext !== undefined ? { cleartextTrafficPermitted: baseCleartext } : {}),
        domainExceptions, pinningDeclared,
      };
      posture.networkSecurityConfig = {
        cleartextTrafficPermitted: baseCleartext ?? null,
        domainExceptions, pinningDeclared,
      };
    } else {
      posture.networkSecurityConfigError = "error" in nscParsed ? nscParsed.error : "unexpected root element";
    }
  }

  const data: NormalizedMobileData = {
    applicationRef: attr(root, "package"),
    platform: "ANDROID",
    ...(attr(root, "versionName") ? { versionName: attr(root, "versionName") } : {}),
    ...(attr(root, "versionCode") ? { versionCode: Number(attr(root, "versionCode")) || undefined } : {}),
    ...(minSdk ? { minOsVersion: minSdk } : {}),
    ...(targetSdk ? { targetOsVersion: targetSdk } : {}),
    permissions, components, deepLinks,
    endpoints: [], nativeLibraries: [], signing: [], sdkInventory: [],
    posture,
    source,
  };
  return { analysis: { data, ...(networkSecurity ? { networkSecurity } : {}) } };
}
