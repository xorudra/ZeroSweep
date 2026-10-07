/**
 * Prompt 17 — mobile posture analysis (§20–§48) + quality gate (§90).
 *
 * The platform analysis engine reasons over the merged static
 * inventory (manifest/plist/network-config/certificates/native
 * libraries) with EVIDENCE discipline:
 *  - an exported component is a finding only when it is exported
 *    WITHOUT permission protection (§21) — and even then the finding
 *    explains that exploitability depends on intent handling;
 *  - dangerous permissions are inventoried, never auto-flagged (§22);
 *  - entitlement/scheme presence alone is never a finding (§38);
 *  - certificate findings come from evidence (debug subject, weak
 *    algorithm, expiry) — never from a name alone (§32);
 *  - MASVS control assessments are evidence statements with the
 *    no-certification disclaimer (§48).
 */
import type { NormalizedControlAssessment, NormalizedFinding, NormalizedMobileData, NormalizedSoftwareComponent } from "../findings/finding.types";
import { buildPurl } from "../code/components";
import { MOBILE_RULE_TAXONOMY } from "./taxonomy";
import { analyzeAndroidManifest } from "./manifest";
import { analyzeIosApp } from "./ios";
import { mobArr, mobRec, mobStr, sanitizeMobileText } from "./sanitize";
import { extractMobileEndpoints, redactMobileSecretValues, scanMobileSecrets, scanMobileSourcePatterns, type MobileSourceSnippet } from "./patterns";
import { mergeMobileData, emptyMobileData } from "./merge";
import { parseApktoolOutput, parseGhidraReport, parseJadxOutput, parseMobsfReport, type MobileParserContext } from "./parsers-mobile";
import type { MobilePlatformName } from "./types";

export interface MobileAnalysisContext {
  applicationId?: string;
  buildId?: string;
  buildHash: string;
  applicationRef: string;
  platform: MobilePlatformName;
  /** PRODUCTION builds make debuggable/backup findings live (§23). */
  environment?: string;
  toolSlug: string;
}

export interface MobilePostureResult {
  findings: NormalizedFinding[];
  controlAssessments: NormalizedControlAssessment[];
}

function tax(ruleId: string): { owaspCategory?: string; cwe?: string; masvsControl?: string } {
  const t = MOBILE_RULE_TAXONOMY[ruleId];
  return t ? { owaspCategory: t.owaspMobile, ...(t.cwe ? { cwe: t.cwe } : {}), ...(t.masvsControl ? { masvsControl: t.masvsControl } : {}) } : {};
}

function finding(
  ctx: MobileAnalysisContext,
  ruleId: string,
  title: string,
  description: string,
  severity: NormalizedFinding["severity"],
  component: string,
  findingType: NormalizedFinding["mobileFindingType"],
  evidence?: string,
): NormalizedFinding {
  const t = tax(ruleId);
  return {
    title, description, severity, confidence: 0.85,
    ...(t.cwe ? { cwe: t.cwe } : {}),
    ...(t.owaspCategory ? { owaspCategory: t.owaspCategory } : {}),
    remediation: undefined,
    references: [],
    sourceTool: ctx.toolSlug,
    sourceFingerprint: `mobile-analysis:${ruleId}:${component}`,
    ruleId,
    mobileApplicationId: ctx.applicationId,
    mobileBuildId: ctx.buildId,
    mobileBuildHash: ctx.buildHash,
    mobilePlatform: ctx.platform,
    mobileFindingType: findingType,
    mobileComponent: component,
    ...(t.masvsControl ? { masvsControl: t.masvsControl } : {}),
    ...(evidence ? { evidence } : {}),
  };
}

export function analyzeMobilePosture(data: NormalizedMobileData, ctx: MobileAnalysisContext): MobilePostureResult {
  const findings: NormalizedFinding[] = [];
  const assessments: NormalizedControlAssessment[] = [];
  const posture = (data.posture ?? {}) as Record<string, unknown>;
  const production = (ctx.environment ?? "UNKNOWN").toUpperCase() === "PRODUCTION";
  const appRef = ctx.applicationRef;
  const assess = (controlId: string, status: NormalizedControlAssessment["status"], evidence: string) => {
    assessments.push({ frameworkKey: "OWASP_MASVS", controlId, subjectRef: appRef, status, evidence });
  };

  // ── Android manifest posture (§20–§27) ──────────────────────────
  if (posture.debuggable === true) {
    findings.push(finding(ctx, "MOBILE_DEBUGGABLE_BUILD",
      "Production build is debuggable", "The application is built with android:debuggable=true. A debuggable production build exposes the app process to inspection and manipulation on any device (§23).",
      production ? "HIGH" : "MEDIUM", "AndroidManifest.xml", "MOBILE_MISCONFIGURATION",
      "android:debuggable=true in the application manifest"));
    assess("MASVS-CODE-1", "FAIL", "debuggable build detected");
  } else if (posture.debuggable === false) {
    assess("MASVS-CODE-1", "PASS", "android:debuggable=false");
  }
  if (posture.allowBackup === true) {
    findings.push(finding(ctx, "MOBILE_BACKUP_ALLOWED",
      "Application data can be backed up", "android:allowBackup=true permits application data extraction through backup mechanisms unless data-extraction rules restrict it (§23, version-aware).",
      "MEDIUM", "AndroidManifest.xml", "MOBILE_MISCONFIGURATION",
      "android:allowBackup=true without restrictive extraction rules"));
    assess("MASVS-STORAGE-2", "FAIL", "allowBackup enabled");
  } else if (posture.allowBackup === false) {
    assess("MASVS-STORAGE-2", "PASS", "android:allowBackup=false");
  }

  // Cleartext (§24): manifest flag OR network-security-config base OR
  // a domain exception — correlated with endpoint evidence below.
  const nsc = (posture.networkSecurityConfig ?? undefined) as undefined | {
    cleartextTrafficPermitted?: boolean | null;
    domainExceptions?: { domain: string; cleartextPermitted: boolean }[];
    pinningDeclared?: boolean;
  };
  let cleartext = posture.usesCleartextTraffic === true || nsc?.cleartextTrafficPermitted === true;
  const cleartextDomains = (nsc?.domainExceptions ?? []).filter((d) => d.cleartextPermitted);
  if (cleartextDomains.length > 0) cleartext = true;
  const httpEndpoints = data.endpoints.filter((e) => e.kind === "HTTP");
  if (cleartext) {
    findings.push(finding(ctx, "MOBILE_CLEARTEXT_ENABLED",
      "Cleartext traffic is permitted", "The application permits cleartext (HTTP) traffic through its manifest / network security configuration. Cleartext traffic can be read and modified by network attackers (§24).",
      "HIGH", "network-security-config", "MOBILE_NETWORK_FINDING",
      cleartextDomains.length > 0
        ? `cleartext exceptions for: ${cleartextDomains.map((d) => d.domain).join(", ")}`
        : "usesCleartextTraffic / cleartextTrafficPermitted enabled"));
    assess("MASVS-NETWORK-1", "FAIL", "cleartext traffic permitted by configuration");
    if (nsc && !nsc.pinningDeclared) {
      findings.push(finding(ctx, "MOBILE_PINNING_ABSENT_OBSERVED_CLEARTEXT",
        "No certificate pinning declared while cleartext is permitted", "No pin-set is declared in the network security configuration and cleartext traffic is permitted — traffic protection relies entirely on platform defaults (§67, observation).",
        "LOW", "network-security-config", "MOBILE_NETWORK_FINDING",
        "no <pin-set> in network security config; cleartext permitted"));
      assess("MASVS-NETWORK-2", "WARN", "no pinning declared; cleartext permitted");
    }
  } else if (httpEndpoints.length > 0) {
    findings.push(finding(ctx, "MOBILE_CLEARTEXT_ENABLED",
      "Cleartext endpoints referenced by the application", "Static extraction found HTTP (cleartext) endpoints referenced by the application although its configuration does not explicitly permit cleartext (§24/§29 correlation).",
      "MEDIUM", "extracted-endpoints", "MOBILE_NETWORK_FINDING",
      httpEndpoints.slice(0, 5).map((e) => e.url).join(", ")));
    assess("MASVS-NETWORK-1", "WARN", "HTTP endpoints extracted from the application");
  } else {
    assess("MASVS-NETWORK-1", "PASS", "no cleartext configuration or HTTP endpoints observed");
  }

  // Exported components (§21): finding ONLY when exported without a
  // permission — protected exports are inventory, not findings.
  let criticalExported = 0;
  for (const comp of data.components) {
    if (!comp.exported || comp.permission) continue;
    const sensitive = comp.intentActions.some((a) => /VIEW|SEND|EDIT|DELETE|MAIN/.test(a)) || comp.kind === "PROVIDER";
    findings.push(finding(ctx, "MOBILE_EXPORTED_COMPONENT_UNPROTECTED",
      `Exported ${comp.kind.toLowerCase()} without permission protection: ${comp.name}`,
      `${comp.name} is exported and declares no permission protection. Whether this is exploitable depends on its intent handling and the sensitivity of the functionality it exposes (§21) — review the component's input validation.`,
      sensitive ? "HIGH" : "MEDIUM", comp.name, "MOBILE_MISCONFIGURATION",
      `exported=true, permission=none, actions=[${comp.intentActions.join(", ")}]`));
    if (sensitive) criticalExported++;
  }
  if (data.components.length > 0) {
    assess("MASVS-PLATFORM-1", criticalExported > 0 ? "FAIL" : "PASS",
      criticalExported > 0 ? `${criticalExported} unprotected exported component(s)` : "no unprotected exported components");
  }

  // ── iOS ATS (§39) ────────────────────────────────────────────────
  const ats = (posture.ats ?? undefined) as undefined | { allowsArbitraryLoads?: boolean; exceptionCount?: number };
  if (ats?.allowsArbitraryLoads === true) {
    findings.push(finding(ctx, "MOBILE_ATS_ARBITRARY_LOADS",
      "App Transport Security allows arbitrary loads", "NSAllowsArbitraryLoads disables ATS protections app-wide, permitting cleartext connections to any domain (§39).",
      "HIGH", "Info.plist", "MOBILE_NETWORK_FINDING", "NSAllowsArbitraryLoads=true"));
    assess("MASVS-NETWORK-1", "FAIL", "ATS arbitrary loads enabled");
  }
  const atsExceptions = ((posture as { atsExceptions?: { domain: string; allowsInsecureHttp: boolean }[] }).atsExceptions ?? [])
    .filter((e) => e.allowsInsecureHttp);
  for (const exc of atsExceptions) {
    findings.push(finding(ctx, "MOBILE_ATS_DOMAIN_EXCEPTION",
      `ATS exception permits insecure HTTP for ${exc.domain}`,
      `The ATS exception for ${exc.domain} allows insecure HTTP loads (§39).`,
      "MEDIUM", exc.domain, "MOBILE_NETWORK_FINDING", `NSExceptionAllowsInsecureHTTPLoads=true for ${exc.domain}`));
  }

  // ── Signing (§31/§32): evidence-based only. ─────────────────────
  for (const cert of data.signing) {
    if (cert.debug) {
      findings.push(finding(ctx, "MOBILE_DEBUG_SIGNING",
        "Build is signed with a debug certificate", "The signing certificate is a debug certificate (subject evidence). Debug-signed builds must never ship to production (§31).",
        production ? "HIGH" : "MEDIUM", cert.subject ?? "signing-certificate", "MOBILE_MISCONFIGURATION",
        `signing subject: ${cert.subject ?? "unknown"}`));
    }
    if (cert.algorithm && /sha1|md5/i.test(cert.algorithm)) {
      findings.push(finding(ctx, "MOBILE_WEAK_SIGNING_ALGORITHM",
        `Weak signing algorithm: ${cert.algorithm}`, "The signing certificate uses a weak signature algorithm (§31).",
        "MEDIUM", cert.subject ?? "signing-certificate", "MOBILE_MISCONFIGURATION",
        `algorithm: ${cert.algorithm}`));
    }
    if (cert.validTo && !Number.isNaN(Date.parse(cert.validTo)) && Date.parse(cert.validTo) < Date.now()) {
      findings.push(finding(ctx, "MOBILE_WEAK_SIGNING_ALGORITHM",
        "Signing certificate is expired", "The signing certificate validity period has ended (§31).",
        "LOW", cert.subject ?? "signing-certificate", "MOBILE_MISCONFIGURATION",
        `validTo: ${cert.validTo}`));
    }
  }

  // ── Native hardening from inventory (§36) — the Ghidra parser
  // emits the same rules from its report; correlation merges them
  // into one canonical finding per library+rule (§52). ────────────
  for (const lib of data.nativeLibraries) {
    const gaps: { ruleId: string; label: string; present?: boolean }[] = [
      { ruleId: "MOBILE_BINARY_NO_PIE", label: "PIE", present: lib.pie },
      { ruleId: "MOBILE_BINARY_NO_NX", label: "NX", present: lib.nx },
      { ruleId: "MOBILE_BINARY_NO_CANARY", label: "stack canaries", present: lib.stackCanary },
    ];
    for (const gap of gaps) {
      if (gap.present === false) {
        findings.push(finding(ctx, gap.ruleId,
          `Native library missing ${gap.label}: ${lib.path}`,
          `Static inventory reports ${gap.label} absent for ${lib.path} (§36).`,
          "MEDIUM", lib.path, "MOBILE_BINARY_FINDING", `${gap.label}=absent in ${lib.path}`));
      }
    }
    if (lib.relro === "NONE") {
      findings.push(finding(ctx, "MOBILE_BINARY_NO_RELRO",
        `Native library without RELRO: ${lib.path}`, `Static inventory reports no RELRO for ${lib.path} (§36).`,
        "LOW", lib.path, "MOBILE_BINARY_FINDING", `relro=NONE in ${lib.path}`));
    }
    if (lib.stripped === false) {
      findings.push(finding(ctx, "MOBILE_BINARY_DEBUG_SYMBOLS",
        `Native library ships debug symbols: ${lib.path}`, `Static inventory reports symbols present in ${lib.path} (§36).`,
        "LOW", lib.path, "MOBILE_BINARY_FINDING", `stripped=false in ${lib.path}`));
    }
  }

  // Root/jailbreak detection (§84): inventoried only — absence is
  // NOT universally a vulnerability, so no finding is emitted either
  // way; the posture fact rides the build record.
  return { findings, controlAssessments: assessments };
}

/** §90 gate inputs: counts over a build's canonical findings. */
export interface MobileGateSummary {
  critical: number;
  verifiedSecrets: number;
  kevDependencies: number;
  criticalExportedComponents: number;
  criticalNetworkMisconfigurations: number;
}

export function summarizeMobileForGate(findings: {
  severity: string;
  ruleId?: string | null;
  mobileFindingType?: string | null;
  secretVerified?: boolean;
  kevListed?: boolean;
}[]): MobileGateSummary {
  return {
    critical: findings.filter((f) => f.severity === "CRITICAL").length,
    verifiedSecrets: findings.filter((f) => f.mobileFindingType === "MOBILE_SECRET" && f.secretVerified).length,
    kevDependencies: findings.filter((f) => f.mobileFindingType === "MOBILE_DEPENDENCY_VULNERABILITY" && f.kevListed).length,
    criticalExportedComponents: findings.filter((f) => f.ruleId === "MOBILE_EXPORTED_COMPONENT_UNPROTECTED" && (f.severity === "CRITICAL" || f.severity === "HIGH")).length,
    criticalNetworkMisconfigurations: findings.filter((f) =>
      (f.ruleId === "MOBILE_CLEARTEXT_ENABLED" || f.ruleId === "MOBILE_ATS_ARBITRARY_LOADS")
      && (f.severity === "CRITICAL" || f.severity === "HIGH")).length,
  };
}

// ── §6 platform extraction over registered analysis artifacts ──────

export interface MobileArtifactExtraction {
  data: NormalizedMobileData;
  findings: NormalizedFinding[];
  components: NormalizedSoftwareComponent[];
}

/**
 * Compose the platform metadata extraction (§6/§19/§20) over a
 * build's REGISTERED analysis artifacts — the bounded, sanitized
 * extraction record created at intake: manifest / plist /
 * network-security-config text, decompiled source snippets, recorded
 * tool outputs (MobSF/JADX/apktool/Ghidra), native-library inventory,
 * signing metadata, dependency + SDK inventory. This is the same
 * composition the adapters perform over live tool output; here it
 * runs deterministically in the platform over stored records.
 * Nothing is executed; every string passes the hostile-content
 * sanitizers inside the underlying parsers.
 */
export function extractMobileArtifacts(
  artifacts: Record<string, unknown>,
  ctx: MobileAnalysisContext,
): MobileArtifactExtraction {
  const parserCtx: MobileParserContext = {
    toolSlug: ctx.toolSlug, applicationRef: ctx.applicationRef,
    platform: ctx.platform, buildHash: ctx.buildHash,
  };
  let data: NormalizedMobileData = {
    ...emptyMobileData(ctx.toolSlug),
    applicationRef: ctx.applicationRef, platform: ctx.platform,
  };
  const findings: NormalizedFinding[] = [];
  const components: NormalizedSoftwareComponent[] = [];
  const absorb = (parsed: { findings: NormalizedFinding[]; mobile?: NormalizedMobileData; components?: NormalizedSoftwareComponent[] }) => {
    findings.push(...parsed.findings);
    if (parsed.mobile) data = mergeMobileData(data, parsed.mobile);
    for (const c of parsed.components ?? []) {
      if (!components.some((x) => x.purl === c.purl)) components.push(c);
    }
  };

  const asText = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);
  const mobsf = asText(artifacts.mobsfReport);
  if (mobsf) absorb(parseMobsfReport(mobsf, parserCtx));
  const jadx = asText(artifacts.jadxOutput);
  if (jadx) absorb(parseJadxOutput(jadx, parserCtx));
  const apktool = asText(artifacts.apktoolOutput);
  if (apktool) absorb(parseApktoolOutput(apktool, parserCtx));
  const ghidra = asText(artifacts.ghidraReport);
  if (ghidra) absorb(parseGhidraReport(ghidra, parserCtx));

  if (ctx.platform === "ANDROID") {
    const manifestXml = asText(artifacts.manifestXml);
    if (manifestXml) {
      const { analysis } = analyzeAndroidManifest(manifestXml, {
        ...(asText(artifacts.networkSecurityConfigXml) ? { networkSecurityConfigXml: asText(artifacts.networkSecurityConfigXml)! } : {}),
        source: ctx.toolSlug,
      });
      if (analysis) data = mergeMobileData(data, analysis.data);
    }
  } else {
    const infoPlistXml = asText(artifacts.infoPlistXml);
    if (infoPlistXml || artifacts.entitlements) {
      const { analysis } = analyzeIosApp({
        ...(infoPlistXml ? { infoPlistXml } : {}),
        ...(artifacts.entitlements ? { entitlements: mobRec(artifacts.entitlements) } : {}),
        source: ctx.toolSlug,
      });
      if (analysis) data = mergeMobileData(data, analysis.data);
    }
  }

  // Decompiled source snippets (§19/§24/§25/§28): endpoint extraction,
  // pattern observations and the metadata-only secret scan — the same
  // composition parseJadxOutput performs. Snippets that persist carry
  // REDACTED text; a secret value exists in no output record.
  const rawSnippets: MobileSourceSnippet[] = mobArr(artifacts.sourceSnippets).map((s) => {
    const rec = mobRec(s);
    return {
      path: sanitizeMobileText(mobStr(rec.path) ?? "unknown", 512),
      text: typeof rec.text === "string" ? rec.text : "",
    };
  }).filter((s) => s.text.length > 0);
  if (rawSnippets.length > 0) {
    const endpoints = extractMobileEndpoints(rawSnippets, ctx.toolSlug);
    if (endpoints.length > 0) data = mergeMobileData(data, { ...emptyMobileData(ctx.toolSlug), endpoints });
    findings.push(...scanMobileSecrets(rawSnippets, parserCtx));
    for (const obs of scanMobileSourcePatterns(rawSnippets)) {
      const t = MOBILE_RULE_TAXONOMY[obs.ruleId];
      findings.push({
        title: `Risky pattern in decompiled source (${obs.ruleId})`,
        description: `Pattern ${obs.ruleId} observed in decompiled application code at ${obs.path}:${obs.line}. Evidence-backed static observation (§25) — decompiled code is analyzed, never executed (§19).`,
        severity: obs.ruleId.includes("WEBVIEW") || obs.ruleId.includes("STORAGE") ? "MEDIUM" : "LOW",
        confidence: 0.7,
        ...(t ? { owaspCategory: t.owaspMobile, ...(t.cwe ? { cwe: t.cwe } : {}) } : {}),
        references: [],
        sourceTool: ctx.toolSlug,
        sourceFingerprint: `${ctx.toolSlug}:${obs.ruleId}:${obs.path}:${obs.line}`,
        ruleId: obs.ruleId,
        filePath: obs.path,
        startLine: obs.line,
        evidence: obs.evidence,
      });
    }
    data = { ...data, sourceSnippets: rawSnippets.map((s) => ({ path: s.path, text: redactMobileSecretValues(s.text) })) };
  }

  // Native library inventory (§33): static properties as recorded at
  // intake — the libraries themselves are never loaded or executed.
  const nativeLibraries = mobArr(artifacts.nativeLibraries).map((entry) => {
    const rec = mobRec(entry);
    return {
      path: sanitizeMobileText(mobStr(rec.path) ?? "unknown.so", 512),
      ...(mobStr(rec.architecture) ? { architecture: mobStr(rec.architecture)! } : {}),
      ...(mobStr(rec.sha256) ? { sha256: mobStr(rec.sha256)! } : {}),
      ...(typeof rec.pie === "boolean" ? { pie: rec.pie } : {}),
      ...(typeof rec.nx === "boolean" ? { nx: rec.nx } : {}),
      ...(typeof rec.stackCanary === "boolean" ? { stackCanary: rec.stackCanary } : typeof rec.canary === "boolean" ? { stackCanary: rec.canary } : {}),
      ...(mobStr(rec.relro) === "NONE" || mobStr(rec.relro) === "PARTIAL" || mobStr(rec.relro) === "FULL" ? { relro: mobStr(rec.relro) as "NONE" | "PARTIAL" | "FULL" } : {}),
      ...(typeof rec.stripped === "boolean" ? { stripped: rec.stripped } : {}),
      source: ctx.toolSlug,
    };
  });
  if (nativeLibraries.length > 0) data = mergeMobileData(data, { ...emptyMobileData(ctx.toolSlug), nativeLibraries });

  const signing = mobArr(artifacts.signing).map((entry) => {
    const rec = mobRec(entry);
    return {
      ...(mobStr(rec.subject) ? { subject: mobStr(rec.subject)! } : {}),
      ...(mobStr(rec.issuer) ? { issuer: mobStr(rec.issuer)! } : {}),
      ...(mobStr(rec.validFrom) ? { validFrom: mobStr(rec.validFrom)! } : {}),
      ...(mobStr(rec.validTo) ? { validTo: mobStr(rec.validTo)! } : {}),
      ...(mobStr(rec.algorithm) ? { algorithm: mobStr(rec.algorithm)! } : {}),
      ...(mobStr(rec.fingerprint) ? { fingerprint: mobStr(rec.fingerprint)! } : {}),
      ...(typeof rec.debug === "boolean" ? { debug: rec.debug } : {}),
      source: ctx.toolSlug,
    };
  });
  if (signing.length > 0) data = mergeMobileData(data, { ...emptyMobileData(ctx.toolSlug), signing });

  // Dependency inventory (§42–§45): versions only as reported at
  // intake — never invented.
  for (const entry of mobArr(artifacts.dependencies)) {
    const rec = mobRec(entry);
    const name = mobStr(rec.name);
    const version = mobStr(rec.version);
    const ecosystem = mobStr(rec.ecosystem);
    if (!name || !version || !ecosystem) continue;
    const purl = buildPurl(ecosystem, name, version);
    if (!components.some((c) => c.purl === purl)) {
      components.push({
        name, version, ecosystem, purl,
        sourceManifest: "mobile-build-intake",
        scope: "UNKNOWN", dependencyScope: "RUNTIME", licenses: [],
      });
    }
  }
  const sdkInventory = mobArr(artifacts.sdkNames ?? artifacts.sdkInventory).map((entry) => {
    const rec = mobRec(entry);
    return {
      name: sanitizeMobileText(mobStr(rec.name) ?? "unknown", 200),
      category: sanitizeMobileText(mobStr(rec.category) ?? "UNKNOWN", 64),
      source: ctx.toolSlug,
    };
  });
  if (sdkInventory.length > 0) data = mergeMobileData(data, { ...emptyMobileData(ctx.toolSlug), sdkInventory });

  return { data, findings, components };
}
