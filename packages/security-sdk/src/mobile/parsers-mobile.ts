/**
 * Prompt 17 — tool output parsers (§17–§19/§34/§62): MobSF reports,
 * JADX decompilation summaries, apktool output, Ghidra headless
 * reports and mitmproxy flow metadata.
 *
 * Every parser is defensive: bounded JSON (sanitize.ts), sanitized
 * strings, secret redaction, and NO invented data — a field the tool
 * did not report stays absent (§45). Decompiled code is never
 * executed (§19); Ghidra output is static metadata only (§34).
 */
import { buildPurl } from "../code/components";
import type { NormalizedFinding, NormalizedMobileData, NormalizedSoftwareComponent } from "../findings/finding.types";
import { analyzeAndroidManifest } from "./manifest";
import { extractMobileEndpoints, redactMobileSecretValues, scanMobileSecrets, scanMobileSourcePatterns } from "./patterns";
import { mobArr, mobBool, mobNum, mobRec, mobStr, mobStrList, parseBoundedMobileJson, sanitizeMobileText } from "./sanitize";
import { MOBILE_RULE_TAXONOMY } from "./taxonomy";
import { emptyParsedMobile, type ParsedMobile } from "./types";

export interface MobileParserContext {
  toolSlug: string;
  applicationRef: string;
  platform: "ANDROID" | "IOS";
  buildHash: string;
}

const SEVERITY_MAP: Record<string, NormalizedFinding["severity"]> = {
  critical: "CRITICAL", high: "HIGH", warning: "MEDIUM", medium: "MEDIUM",
  low: "LOW", info: "INFORMATIONAL", information: "INFORMATIONAL", good: "INFORMATIONAL",
};

function severityOf(v: unknown, fallback: NormalizedFinding["severity"] = "MEDIUM"): NormalizedFinding["severity"] {
  if (typeof v !== "string") return fallback;
  return SEVERITY_MAP[v.toLowerCase()] ?? fallback;
}

function taxonomyFields(ruleId: string): { owaspCategory?: string; cwe?: string } {
  const t = MOBILE_RULE_TAXONOMY[ruleId];
  return t ? { owaspCategory: t.owaspMobile, ...(t.cwe ? { cwe: t.cwe } : {}) } : {};
}

/** Map a MobSF manifest/code finding title to a governed rule id.
 *  Unknown titles keep a generic rule — never an invented mapping. */
function mobsfRuleId(title: string, section: string): string {
  const t = title.toLowerCase();
  if (/cleartext/.test(t)) return "MOBILE_CLEARTEXT_ENABLED";
  if (/debuggable/.test(t)) return "MOBILE_DEBUGGABLE_BUILD";
  if (/backup/.test(t)) return "MOBILE_BACKUP_ALLOWED";
  if (/exported/.test(t)) return "MOBILE_EXPORTED_COMPONENT_UNPROTECTED";
  if (/hardcoded|secret|api.?key/.test(t)) return "MOBILE_HARDCODED_SECRET";
  if (/weak|md5|sha1|ecb|des\b/.test(t)) return "MOBILE_WEAK_CRYPTOGRAPHY";
  if (/certificate|signing|janus/.test(t)) return "MOBILE_WEAK_SIGNING_ALGORITHM";
  if (/webview/.test(t)) return "MOBILE_WEBVIEW_JS_BRIDGE";
  if (/world readable|world-readable|file permission/.test(t)) return "MOBILE_WORLD_READABLE_STORAGE";
  return section === "manifest" ? "MOBILE_MANIFEST_FINDING" : "MOBILE_CODE_FINDING_GENERIC";
}

/**
 * MobSF static-analysis report (§17). MobSF severity/title/file/CWE/
 * OWASP/MASVS fields are normalized; MobSF's own MASVS/OWASP labels
 * are preserved as the tool's claims (the platform adds no
 * certification claim of its own, §48).
 */
export function parseMobsfReport(text: string, ctx: MobileParserContext): ParsedMobile {
  const root = mobRec(parseBoundedMobileJson(text, { what: "mobsf report" }));
  if (Object.keys(root).length === 0) return emptyParsedMobile({ parseErrors: 1 });
  const findings: NormalizedFinding[] = [];

  const permissions: NormalizedMobileData["permissions"] = [];
  for (const [name, meta] of Object.entries(mobRec(root.permissions))) {
    const m = mobRec(meta);
    const status = typeof m.status === "string" ? m.status.toLowerCase() : "";
    permissions.push({
      name: sanitizeMobileText(name, 256),
      classification: status === "dangerous" ? "DANGEROUS" : status === "signature" ? "SIGNATURE" : status === "normal" ? "NORMAL" : "UNKNOWN",
      source: ctx.toolSlug,
    });
  }

  const manifestAnalysis = mobRec(root.manifest_analysis);
  for (const f of mobArr(manifestAnalysis.manifest_findings)) {
    const rec = mobRec(f);
    const title = mobStr(rec.title) ?? mobStr(rec.name) ?? "MobSF manifest finding";
    const ruleId = mobsfRuleId(title, "manifest");
    findings.push({
      title,
      description: mobStr(rec.description) ?? mobStr(rec.rule) ?? title,
      severity: severityOf(rec.severity),
      confidence: 0.8,
      ...taxonomyFields(ruleId),
      ...(mobStr(rec.cwe) ? { cwe: mobStr(rec.cwe) } : {}),
      remediation: mobStr(rec.remediation),
      references: mobStrList(rec.ref, 8),
      sourceTool: ctx.toolSlug,
      sourceFingerprint: `mobsf:${ruleId}:${sanitizeMobileText(title, 120)}`,
      ruleId,
      evidence: mobStr(rec.component) ?? undefined,
    });
  }

  const codeAnalysis = mobRec(root.code_analysis);
  const codeFindings = mobRec(codeAnalysis.findings);
  for (const [key, value] of Object.entries(codeFindings)) {
    const rec = mobRec(value);
    const files = mobRec(rec.files);
    const firstFile = Object.keys(files)[0];
    const title = mobStr(mobRec(rec.metadata).description) ?? sanitizeMobileText(key, 160);
    const ruleId = mobsfRuleId(title || key, "code");
    findings.push({
      title: title || "MobSF code finding",
      description: title || "MobSF code analysis finding",
      severity: severityOf(mobRec(rec.metadata).severity),
      confidence: 0.75,
      ...taxonomyFields(ruleId),
      ...(mobStr(mobRec(rec.metadata).cwe) ? { cwe: mobStr(mobRec(rec.metadata).cwe) } : {}),
      remediation: mobStr(mobRec(rec.metadata).remediation),
      references: [],
      sourceTool: ctx.toolSlug,
      sourceFingerprint: `mobsf:${ruleId}:${sanitizeMobileText(key, 120)}`,
      ruleId,
      ...(firstFile ? { filePath: sanitizeMobileText(firstFile, 512) } : {}),
    });
  }

  // Certificate / signing analysis (§31).
  const signing: NormalizedMobileData["signing"] = [];
  const certAnalysis = mobRec(root.certificate_analysis);
  const certInfo = mobRec(certAnalysis.certificate_info);
  if (Object.keys(certInfo).length > 0) {
    signing.push({
      ...(mobStr(certInfo.subject) ? { subject: mobStr(certInfo.subject) } : {}),
      ...(mobStr(certInfo.issuer) ? { issuer: mobStr(certInfo.issuer) } : {}),
      ...(mobStr(certInfo.fingerprint) ? { fingerprint: mobStr(certInfo.fingerprint) } : {}),
      ...(mobStr(certInfo.algorithm) ? { algorithm: mobStr(certInfo.algorithm) } : {}),
      debug: /debug/i.test(mobStr(certInfo.subject) ?? ""),
      source: ctx.toolSlug,
    });
  }
  for (const f of mobArr(certAnalysis.certificate_findings)) {
    const rec = mobRec(f);
    const title = mobStr(rec.title) ?? "MobSF certificate finding";
    findings.push({
      title,
      description: mobStr(rec.description) ?? title,
      severity: severityOf(rec.severity, "LOW"),
      confidence: 0.8,
      ...taxonomyFields("MOBILE_WEAK_SIGNING_ALGORITHM"),
      references: [],
      sourceTool: ctx.toolSlug,
      sourceFingerprint: `mobsf:MOBILE_WEAK_SIGNING_ALGORITHM:${sanitizeMobileText(title, 120)}`,
      ruleId: "MOBILE_WEAK_SIGNING_ALGORITHM",
    });
  }

  // URLs/domains MobSF extracted (§29): DISCOVERED_REFERENCEs only.
  const endpoints: NormalizedMobileData["endpoints"] = [];
  const urls = new Set<string>([...mobStrList(root.urls, 500)]);
  for (const u of mobArr(root.urls)) {
    const rec = mobRec(u);
    if (typeof rec.url === "string") urls.add(rec.url);
  }
  for (const url of urls) {
    try {
      const parsed = new URL(url);
      endpoints.push({
        url: sanitizeMobileText(url, 512), host: parsed.hostname.toLowerCase(),
        kind: parsed.protocol === "wss:" || parsed.protocol === "ws:" ? "WEBSOCKET" : parsed.protocol === "https:" ? "HTTPS" : "HTTP",
        classification: "DISCOVERED_REFERENCE", source: ctx.toolSlug,
      });
    } catch { /* not a URL — dropped, never guessed */ }
  }
  const trackers = mobArr(root.trackers).map((t) => mobRec(t)).filter((t) => typeof t.name === "string");
  const sdkInventory = trackers.map((t) => ({
    name: sanitizeMobileText(String(t.name), 128),
    category: "TRACKER_OR_SDK",
    source: ctx.toolSlug,
  }));

  const data: NormalizedMobileData = {
    applicationRef: mobStr(root.package_name) ?? ctx.applicationRef,
    platform: ctx.platform,
    ...(mobStr(root.version_name) ? { versionName: mobStr(root.version_name) } : {}),
    ...(mobNum(root.version_code) !== undefined ? { versionCode: mobNum(root.version_code) } : {}),
    ...(mobStr(root.min_sdk) ? { minOsVersion: mobStr(root.min_sdk) } : {}),
    ...(mobStr(root.target_sdk) ? { targetOsVersion: mobStr(root.target_sdk) } : {}),
    permissions,
    components: [], deepLinks: [], endpoints,
    nativeLibraries: [], signing, sdkInventory,
    source: ctx.toolSlug,
  };
  return {
    findings, mobile: data,
    metrics: { findings: findings.length, endpoints: endpoints.length, permissions: permissions.length },
  };
}

/**
 * JADX decompilation summary (§19): JADX runs over the artifact in
 * the sandbox; ZeroSweep consumes its structured summary (decompiled
 * file inventory + source text of governed interest). Decompiled
 * source is sensitive data (§24) — it is scanned for secrets and
 * patterns here and never returned raw.
 */
export function parseJadxOutput(text: string, ctx: MobileParserContext): ParsedMobile {
  const root = mobRec(parseBoundedMobileJson(text, { what: "jadx output" }));
  if (Object.keys(root).length === 0) return emptyParsedMobile({ parseErrors: 1 });
  const rawSnippets = mobArr(root.sourceFiles).map((f) => {
    const rec = mobRec(f);
    return {
      path: sanitizeMobileText(typeof rec.path === "string" ? rec.path : "unknown", 512),
      text: typeof rec.text === "string" ? rec.text : "",
    };
  }).filter((s) => s.text.length > 0);
  // §28/§106: scanning happens over the raw text INSIDE the parser;
  // the snippets that leave the parser carry secret-redacted text —
  // a secret value exists in no output record.
  const snippets = rawSnippets.map((s) => ({ path: s.path, text: redactMobileSecretValues(s.text) }));

  const endpoints = extractMobileEndpoints(rawSnippets, ctx.toolSlug);
  const observations = scanMobileSourcePatterns(rawSnippets);
  const secretFindings = scanMobileSecrets(rawSnippets, ctx);
  const findings: NormalizedFinding[] = [...secretFindings];
  for (const obs of observations) {
    findings.push({
      title: `Risky pattern in decompiled source (${obs.ruleId})`,
      description: `Pattern ${obs.ruleId} observed in decompiled application code at ${obs.path}:${obs.line}. Evidence-backed static observation (§25) — decompiled code is analyzed, never executed (§19).`,
      severity: obs.ruleId.includes("WEBVIEW") || obs.ruleId.includes("STORAGE") ? "MEDIUM" : "LOW",
      confidence: 0.7,
      ...taxonomyFields(obs.ruleId),
      references: [],
      sourceTool: ctx.toolSlug,
      sourceFingerprint: `jadx:${obs.ruleId}:${obs.path}:${obs.line}`,
      ruleId: obs.ruleId,
      filePath: obs.path,
      startLine: obs.line,
      evidence: obs.evidence,
    });
  }
  const data: NormalizedMobileData = {
    applicationRef: ctx.applicationRef, platform: ctx.platform,
    permissions: [], components: [], deepLinks: [], endpoints,
    nativeLibraries: [], signing: [], sdkInventory: [],
    sourceSnippets: snippets,
    source: ctx.toolSlug,
  };
  return { findings, mobile: data, metrics: { findings: findings.length, sourceFiles: snippets.length, endpoints: endpoints.length } };
}

/**
 * apktool output (§18): the decoded AndroidManifest.xml text + the
 * extracted file inventory. The manifest goes through the platform
 * manifest analyzer; library files feed the native inventory. The
 * extraction itself happened in the tool's safe workspace (§18) —
 * ZeroSweep consumes listings + text, never extracted binaries.
 */
export function parseApktoolOutput(text: string, ctx: MobileParserContext): ParsedMobile {
  const root = mobRec(parseBoundedMobileJson(text, { what: "apktool output" }));
  if (Object.keys(root).length === 0) return emptyParsedMobile({ parseErrors: 1 });
  const manifestXml = typeof root.manifestXml === "string" ? root.manifestXml : undefined;
  const nscXml = typeof root.networkSecurityConfigXml === "string" ? root.networkSecurityConfigXml : undefined;
  let data: NormalizedMobileData | undefined;
  if (manifestXml) {
    const { analysis, error } = analyzeAndroidManifest(manifestXml, {
      ...(nscXml ? { networkSecurityConfigXml: nscXml } : {}),
      source: ctx.toolSlug,
    });
    if (analysis) data = analysis.data;
    else return emptyParsedMobile({ parseErrors: 1, manifestError: error ? 1 : 0 });
  }
  const files = mobStrList(root.files, 20000);
  const nativeLibraries: NormalizedMobileData["nativeLibraries"] = files
    .filter((f) => /^lib\/[^/]+\/[^/]+\.so$/.test(f))
    .map((f) => ({
      path: f,
      architecture: f.split("/")[1],
      source: ctx.toolSlug,
    }));
  const components: NormalizedSoftwareComponent[] = [];
  for (const line of mobStrList(root.dependencyHints, 2000)) {
    // apktool does not resolve dependencies; hints are "ecosystem:name:version"
    // strings from resource analysis — versions are never invented (§45).
    const parts = line.split(":");
    if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
      components.push({
        name: parts[1]!, version: parts[2]!, ecosystem: parts[0]!,
        purl: buildPurl(parts[0]!, parts[1]!, parts[2]!),
        sourceManifest: "apktool-resource-analysis",
        scope: "UNKNOWN", dependencyScope: "RUNTIME", licenses: [],
      });
    }
  }
  const merged: NormalizedMobileData = {
    ...(data ?? {
      applicationRef: ctx.applicationRef, platform: ctx.platform,
      permissions: [], components: [], deepLinks: [], endpoints: [],
      nativeLibraries: [], signing: [], sdkInventory: [], source: ctx.toolSlug,
    }),
    nativeLibraries: [...(data?.nativeLibraries ?? []), ...nativeLibraries],
  };
  return {
    findings: [], mobile: merged,
    ...(components.length > 0 ? { components } : {}),
    metrics: { files: files.length, nativeLibraries: nativeLibraries.length },
  };
}

/**
 * Ghidra headless static report (§34–§36): function/string inventory
 * + binary hardening properties per native library. Headless/static
 * only — the native binary is never executed, and only
 * administrator-approved analysis scripts produce this report (§35).
 */
export function parseGhidraReport(text: string, ctx: MobileParserContext): ParsedMobile {
  const root = mobRec(parseBoundedMobileJson(text, { what: "ghidra report" }));
  if (Object.keys(root).length === 0) return emptyParsedMobile({ parseErrors: 1 });
  const libraries: NormalizedMobileData["nativeLibraries"] = [];
  const findings: NormalizedFinding[] = [];
  for (const entry of mobArr(root.libraries)) {
    const rec = mobRec(entry);
    const path = mobStr(rec.path) ?? "unknown.so";
    const hardening = mobRec(rec.hardening);
    const lib: NormalizedMobileData["nativeLibraries"][number] = {
      path,
      ...(mobStr(rec.architecture) ? { architecture: mobStr(rec.architecture) } : {}),
      ...(mobStr(rec.sha256) ? { sha256: mobStr(rec.sha256) } : {}),
      ...(mobBool(hardening.pie) !== undefined ? { pie: mobBool(hardening.pie) } : {}),
      ...(mobBool(hardening.nx) !== undefined ? { nx: mobBool(hardening.nx) } : {}),
      ...(mobBool(hardening.stackCanary) !== undefined ? { stackCanary: mobBool(hardening.stackCanary) } : {}),
      ...(mobStr(hardening.relro) ? { relro: mobStr(hardening.relro) as "NONE" | "PARTIAL" | "FULL" } : {}),
      ...(mobBool(hardening.stripped) !== undefined ? { stripped: mobBool(hardening.stripped) } : {}),
      source: ctx.toolSlug,
    };
    libraries.push(lib);
    // §36 binary hardening findings — from reported properties only.
    const gaps: { ruleId: string; label: string; present: boolean | undefined }[] = [
      { ruleId: "MOBILE_BINARY_NO_PIE", label: "PIE (position-independent executable)", present: lib.pie },
      { ruleId: "MOBILE_BINARY_NO_NX", label: "NX (non-executable stack)", present: lib.nx },
      { ruleId: "MOBILE_BINARY_NO_CANARY", label: "stack canaries", present: lib.stackCanary },
    ];
    for (const gap of gaps) {
      if (gap.present === false) {
        findings.push({
          title: `Native library missing ${gap.label}: ${path}`,
          description: `Static binary analysis reports ${gap.label} absent for ${path}. Hardening gaps raise exploitation cost concerns for native-code vulnerabilities (§36).`,
          severity: "MEDIUM", confidence: 0.85,
          ...taxonomyFields(gap.ruleId),
          references: [],
          sourceTool: ctx.toolSlug,
          sourceFingerprint: `ghidra:${gap.ruleId}:${path}`,
          ruleId: gap.ruleId,
          filePath: path,
        });
      }
    }
    if (lib.relro === "NONE") {
      findings.push({
        title: `Native library without RELRO: ${path}`,
        description: `Static binary analysis reports no RELRO for ${path} (§36).`,
        severity: "LOW", confidence: 0.85,
        ...taxonomyFields("MOBILE_BINARY_NO_RELRO"),
        references: [], sourceTool: ctx.toolSlug,
        sourceFingerprint: `ghidra:MOBILE_BINARY_NO_RELRO:${path}`,
        ruleId: "MOBILE_BINARY_NO_RELRO", filePath: path,
      });
    }
    if (lib.stripped === false) {
      findings.push({
        title: `Native library ships debug symbols: ${path}`,
        description: `Static binary analysis reports symbols/debug information present in ${path}, easing reverse engineering (§36).`,
        severity: "LOW", confidence: 0.8,
        ...taxonomyFields("MOBILE_BINARY_DEBUG_SYMBOLS"),
        references: [], sourceTool: ctx.toolSlug,
        sourceFingerprint: `ghidra:MOBILE_BINARY_DEBUG_SYMBOLS:${path}`,
        ruleId: "MOBILE_BINARY_DEBUG_SYMBOLS", filePath: path,
      });
    }
  }
  const data: NormalizedMobileData = {
    applicationRef: ctx.applicationRef, platform: ctx.platform,
    permissions: [], components: [], deepLinks: [], endpoints: [],
    nativeLibraries: libraries, signing: [], sdkInventory: [],
    source: ctx.toolSlug,
  };
  return { findings, mobile: data, metrics: { findings: findings.length, libraries: libraries.length } };
}

/**
 * mitmproxy flow metadata (§62–§68): sanitized hosts/methods/paths/
 * status/TLS metadata + discovered endpoints. Bodies are NEVER part
 * of this record (§66) — a flow entry carrying a body key is dropped
 * to metadata, and secret-shaped values are redacted by the
 * sanitizers.
 */
export function parseMitmproxyFlows(text: string, ctx: MobileParserContext): ParsedMobile {
  const root = mobRec(parseBoundedMobileJson(text, { what: "mitmproxy flows" }));
  if (Object.keys(root).length === 0) return emptyParsedMobile({ parseErrors: 1 });
  const endpoints: NormalizedMobileData["endpoints"] = [];
  const findings: NormalizedFinding[] = [];
  const seenCleartext = new Set<string>();
  for (const flow of mobArr(root.flows)) {
    const rec = mobRec(flow);
    const host = mobStr(rec.host);
    if (!host) continue;
    const scheme = (mobStr(rec.scheme) ?? "https").toLowerCase();
    const path = mobStr(rec.path) ?? "/";
    const url = sanitizeMobileText(`${scheme}://${host}${path.startsWith("/") ? path : `/${path}`}`, 512);
    endpoints.push({
      url, host: host.toLowerCase(),
      kind: scheme === "http" ? "HTTP" : "HTTPS",
      classification: "DISCOVERED_REFERENCE", source: ctx.toolSlug,
    });
    // §86: runtime cleartext observation — a dynamic observation that
    // can confirm a static cleartext finding (§88).
    if (scheme === "http" && !seenCleartext.has(host.toLowerCase())) {
      seenCleartext.add(host.toLowerCase());
      findings.push({
        title: `Cleartext HTTP traffic observed to ${host}`,
        description: "The lab proxy observed unencrypted HTTP traffic from the application under test (§62/§86). This is a runtime observation from the controlled lab only.",
        severity: "HIGH", confidence: 0.95,
        ...taxonomyFields("MOBILE_RUNTIME_CLEARTEXT_TRAFFIC"),
        references: [], sourceTool: ctx.toolSlug,
        sourceFingerprint: `mitmproxy:MOBILE_RUNTIME_CLEARTEXT_TRAFFIC:${host.toLowerCase()}`,
        ruleId: "MOBILE_RUNTIME_CLEARTEXT_TRAFFIC",
        endpoint: url, host: host.toLowerCase(),
      });
    }
  }
  const data: NormalizedMobileData = {
    applicationRef: ctx.applicationRef, platform: ctx.platform,
    permissions: [], components: [], deepLinks: [], endpoints,
    nativeLibraries: [], signing: [], sdkInventory: [],
    source: ctx.toolSlug,
  };
  return { findings, mobile: data, metrics: { flows: endpoints.length, findings: findings.length } };
}
