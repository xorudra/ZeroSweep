import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { createStoredZip } from "../code/archive";
import {
  extractMobileArtifacts, fixtureAnalysisArtifacts,
  ATTACK_ARCHIVE_ENTRIES, FIXTURE_ANDROID_MANIFEST_XML, FIXTURE_BUILD_HASH,
  FIXTURE_DECOMPILED_SOURCES, FIXTURE_GHIDRA_REPORT, FIXTURE_INFO_PLIST_XML,
  FIXTURE_IOS_ENTITLEMENTS, FIXTURE_MOBILE_BUILD_RECORD, FIXTURE_MOBSF_REPORT,
  FIXTURE_NETWORK_SECURITY_CONFIG_XML, FIXTURE_SECRET_VALUE,
  MOBILE_DISABLED_REGISTRATIONS, PROHIBITED_MOBILE_AUTOMATION,
  analyzeAndroidManifest, analyzeIosApp, analyzeMobilePosture,
  canonicalMobileFingerprint, correlateMobileFindings, createFixtureMobileDeps,
  createMobileAdapters, crossBuildKeyFor, evaluateInstrumentationPolicy,
  evaluateMobileSecurityGate, extractMobileEndpoints, FixtureToolRunner,
  mobileCrossBuildKey, mobileFindingFingerprint, mobileHealthBySlug,
  parseApktoolOutput, parseGhidraReport, parseJadxOutput, parseMitmproxyFlows,
  parseMobsfReport, scanMobileSecrets, sha256Hex, sniffMobileArtifact,
  summarizeMobileForGate, validateMobileArtifactUpload,
  FIXTURE_JADX_OUTPUT, FIXTURE_APKTOOL_OUTPUT, FIXTURE_MOBILE_MITMPROXY_FLOWS,
  type InstrumentationModuleRecord,
} from "../index";

const CTX = { toolSlug: "mobsf", applicationRef: "com.example.app", platform: "ANDROID" as const, buildHash: FIXTURE_BUILD_HASH };
const IDENTITY = { applicationRef: "com.example.app", buildHash: FIXTURE_BUILD_HASH, platform: "ANDROID" };

function fixtureApkBytes(): Uint8Array {
  return createStoredZip([
    { name: "AndroidManifest.xml", data: "<manifest/>" },
    { name: "classes.dex", data: "dex-bytes" },
    { name: "lib/arm64-v8a/libexample.so", data: "elf-bytes" },
  ]);
}

describe("Prompt 17 intake (§5/§6/§107)", () => {
  it("identifies artifacts by magic bytes + required entries, never by name", () => {
    const apk = fixtureApkBytes();
    expect(sniffMobileArtifact(apk, ["AndroidManifest.xml", "classes.dex"])).toBe("APK");
    expect(sniffMobileArtifact(new TextEncoder().encode("dex\n035\0"))).toBe("DEX");
    expect(sniffMobileArtifact(new TextEncoder().encode("plain text"))).toBe("UNKNOWN");
    const out = validateMobileArtifactUpload({ fileName: "renamed.ipa", bytes: apk });
    expect(out.ok).toBe(false); // extension lies about the content
    expect(out.errors.join(" ")).toMatch(/extension claims IPA but the content is APK/);
    const good = validateMobileArtifactUpload({ fileName: "app.apk", bytes: apk });
    expect(good.ok).toBe(true);
    expect(good.format).toBe("APK");
    expect(good.artifactHash).toBe(createHash("sha256").update(apk).digest("hex"));
  });

  it("rejects a declared hash that does not match the bytes (§5)", () => {
    const out = validateMobileArtifactUpload({ fileName: "app.apk", bytes: fixtureApkBytes(), declaredSha256: "0".repeat(64) });
    expect(out.ok).toBe(false);
    expect(out.errors.join(" ")).toMatch(/does not match/);
  });

  it("rejects every archive attack (§107): traversal, absolute, symlink, bomb, nested", () => {
    for (const [name, entries] of Object.entries(ATTACK_ARCHIVE_ENTRIES)) {
      const out = validateMobileArtifactUpload({
        fileName: "app.apk", entries,
        declaredSha256: "a".repeat(64),
        bytes: undefined,
      });
      expect(out.ok, name).toBe(false);
    }
    const bomb = validateMobileArtifactUpload({ fileName: "app.apk", entries: ATTACK_ARCHIVE_ENTRIES.bomb, declaredSha256: "a".repeat(64) });
    expect(bomb.errors.join(" ")).toMatch(/compression ratio|exceeds/);
    const slip = validateMobileArtifactUpload({ fileName: "app.apk", entries: ATTACK_ARCHIVE_ENTRIES.traversal, declaredSha256: "a".repeat(64) });
    expect(slip.errors.join(" ")).toMatch(/escapes the archive root/);
  });
});

describe("Prompt 17 manifest analysis (§20–§27)", () => {
  const { analysis } = analyzeAndroidManifest(FIXTURE_ANDROID_MANIFEST_XML, {
    networkSecurityConfigXml: FIXTURE_NETWORK_SECURITY_CONFIG_XML,
  });

  it("inventories permissions with classifications — dangerous is NOT a finding (§22)", () => {
    const perms = analysis!.data.permissions;
    expect(perms.find((p) => p.name.endsWith("CAMERA"))?.classification).toBe("DANGEROUS");
    expect(perms.find((p) => p.name.endsWith("INTERNET"))?.classification).toBe("NORMAL");
    expect(perms.find((p) => p.name.includes("com.example"))?.classification).toBe("CUSTOM");
  });

  it("inventories components + deep links without invoking anything (§21/§26)", () => {
    const comps = analysis!.data.components;
    expect(comps.find((c) => c.name === ".SyncService")?.exported).toBe(true);
    expect(comps.find((c) => c.name === ".GuardedService")?.permission).toContain("INTERNAL");
    expect(comps.find((c) => c.name === ".SettingsActivity")?.exported).toBe(false);
    const links = analysis!.data.deepLinks;
    expect(links.some((l) => l.scheme === "https" && l.host === "app.example.com" && l.autoVerify)).toBe(true);
    expect(links.some((l) => l.scheme === "exampleapp")).toBe(true);
  });

  it("posture engine flags debuggable/backup/cleartext and ONLY unprotected exports (§21/§23/§24)", () => {
    const posture = analyzeMobilePosture(analysis!.data, {
      buildHash: FIXTURE_BUILD_HASH, applicationRef: "com.example.app", platform: "ANDROID",
      environment: "PRODUCTION", toolSlug: "mobile-platform-analysis",
    });
    const rules = posture.findings.map((f) => f.ruleId);
    expect(rules).toContain("MOBILE_DEBUGGABLE_BUILD");
    expect(rules).toContain("MOBILE_BACKUP_ALLOWED");
    expect(rules).toContain("MOBILE_CLEARTEXT_ENABLED");
    const exported = posture.findings.filter((f) => f.ruleId === "MOBILE_EXPORTED_COMPONENT_UNPROTECTED");
    // MainActivity (MAIN/LAUNCHER), SyncService and DataProvider are
    // unprotected; GuardedService carries a permission → NO finding.
    expect(exported.map((f) => f.mobileComponent)).not.toContain(".GuardedService");
    expect(exported.length).toBe(3);
    expect(posture.controlAssessments.some((a) => a.frameworkKey === "OWASP_MASVS" && a.controlId === "MASVS-NETWORK-1" && a.status === "FAIL")).toBe(true);
    expect(JSON.stringify(posture)).not.toContain(FIXTURE_SECRET_VALUE);
  });

  it("refuses XXE-shaped manifests (§107)", () => {
    const hostile = `<?xml version="1.0"?><!DOCTYPE manifest [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><manifest package="com.example.app"/>`;
    const out = analyzeAndroidManifest(hostile);
    expect(out.error).toMatch(/DOCTYPE\/ENTITY/);
  });

  it("sanitizes hostile strings: markup, ANSI escapes and oversized values render safely (§107)", () => {
    const hostile = FIXTURE_ANDROID_MANIFEST_XML.replace(
      'android:label="Example App"',
      `android:label="&lt;script&gt;alert(1)&lt;/script&gt;\u001b[31mEVIL\u001b[0m ${"x".repeat(5000)}"`,
    );
    const { analysis: a2, error } = analyzeAndroidManifest(hostile);
    expect(error).toBeUndefined();
    expect(a2).toBeDefined();
    const blob = JSON.stringify(a2);
    expect(blob).not.toContain("\u001b");
    expect(blob.length).toBeLessThan(20000); // oversized strings are capped
  });
});

describe("Prompt 17 iOS analysis (§37–§41)", () => {
  it("inventories schemes, usage descriptions and ATS exceptions; presence alone is not a finding (§38)", () => {
    const { analysis } = analyzeIosApp({
      infoPlistXml: FIXTURE_INFO_PLIST_XML,
      entitlements: FIXTURE_IOS_ENTITLEMENTS,
      embeddedFrameworks: ["ExampleKit.framework"],
    });
    expect(analysis!.data.deepLinks.some((l) => l.scheme === "exampleios")).toBe(true);
    expect(analysis!.permissionDescriptions.some((p) => p.key === "NSCameraUsageDescription")).toBe(true);
    expect(analysis!.ats?.allowsArbitraryLoads).toBe(false);
    expect(analysis!.ats?.exceptionDomains[0]?.domain).toBe("legacy.example.com");
    const posture = analyzeMobilePosture(analysis!.data, {
      buildHash: FIXTURE_BUILD_HASH, applicationRef: "com.example.iosapp", platform: "IOS", toolSlug: "mobile-platform-analysis",
    });
    const rules = posture.findings.map((f) => f.ruleId);
    expect(rules).toContain("MOBILE_ATS_DOMAIN_EXCEPTION");
    expect(rules).not.toContain("MOBILE_ATS_ARBITRARY_LOADS");
    // Universal-link entitlement presence produced NO finding (§38).
    expect(posture.findings.every((f) => !/associated|entitlement/i.test(f.title))).toBe(true);
  });
});

describe("Prompt 17 parsers (§17–§19/§34/§62)", () => {
  it("MobSF: normalizes findings, permissions, signing + DISCOVERED_REFERENCE endpoints", () => {
    const parsed = parseMobsfReport(FIXTURE_MOBSF_REPORT, CTX);
    expect(parsed.findings.some((f) => f.ruleId === "MOBILE_DEBUGGABLE_BUILD")).toBe(true);
    expect(parsed.mobile?.signing[0]?.debug).toBe(true);
    expect(parsed.mobile?.endpoints.every((e) => e.classification === "DISCOVERED_REFERENCE")).toBe(true);
    expect(parsed.mobile?.sdkInventory[0]?.name).toBe("Example Analytics SDK");
    expect(JSON.stringify(parsed)).not.toContain(FIXTURE_SECRET_VALUE);
  });

  it("JADX: secrets are fingerprinted + redacted, NEVER returned in full (§28/§106)", () => {
    const parsed = parseJadxOutput(FIXTURE_JADX_OUTPUT, CTX);
    const secret = parsed.findings.find((f) => f.ruleId === "MOBILE_HARDCODED_SECRET");
    expect(secret).toBeDefined();
    expect(secret!.secret?.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(secret!.secret?.redactedPreview).not.toContain("0123456789abcdef");
    expect(JSON.stringify(parsed)).not.toContain(FIXTURE_SECRET_VALUE);
    expect(parsed.findings.some((f) => f.ruleId === "MOBILE_WEBVIEW_JS_BRIDGE")).toBe(true);
    expect(parsed.findings.some((f) => f.ruleId === "MOBILE_WORLD_READABLE_STORAGE")).toBe(true);
    expect(parsed.findings.some((f) => f.ruleId === "MOBILE_SENSITIVE_DATA_LOGGING")).toBe(true);
    expect(parsed.mobile?.endpoints.some((e) => e.url === "http://api.example.com/legacy/ping")).toBe(true);
  });

  it("apktool: manifest goes through the platform analyzer; libraries inventoried", () => {
    const parsed = parseApktoolOutput(FIXTURE_APKTOOL_OUTPUT, CTX);
    expect(parsed.mobile?.applicationRef).toBe("com.example.app");
    expect(parsed.mobile?.nativeLibraries).toHaveLength(2);
    expect(parsed.mobile?.posture?.debuggable).toBe(true);
  });

  it("Ghidra: hardening gaps become binary findings from reported properties only (§36)", () => {
    const parsed = parseGhidraReport(FIXTURE_GHIDRA_REPORT, CTX);
    const rules = parsed.findings.map((f) => f.ruleId);
    expect(rules).toContain("MOBILE_BINARY_NO_PIE");
    expect(rules).toContain("MOBILE_BINARY_NO_CANARY");
    expect(rules).toContain("MOBILE_BINARY_DEBUG_SYMBOLS");
    expect(rules).not.toContain("MOBILE_BINARY_NO_NX"); // nx=true in the fixture
  });

  it("mitmproxy: flow metadata only; cleartext observation becomes a runtime finding (§62/§86)", () => {
    const parsed = parseMitmproxyFlows(FIXTURE_MOBILE_MITMPROXY_FLOWS, CTX);
    expect(parsed.findings.some((f) => f.ruleId === "MOBILE_RUNTIME_CLEARTEXT_TRAFFIC")).toBe(true);
    expect(parsed.mobile?.endpoints).toHaveLength(2);
  });

  it("extracted endpoints are references — never scope (§29/§30)", () => {
    const endpoints = extractMobileEndpoints(FIXTURE_DECOMPILED_SOURCES, "jadx");
    expect(endpoints.length).toBeGreaterThan(0);
    expect(endpoints.every((e) => e.classification === "DISCOVERED_REFERENCE")).toBe(true);
  });

  it("secret scan drops obvious placeholders (§28)", () => {
    const findings = scanMobileSecrets(
      [{ path: "a.java", text: "String API_KEY = \"example-placeholder-value\";" }],
      { applicationRef: "com.example.app", platform: "ANDROID", buildHash: FIXTURE_BUILD_HASH, toolSlug: "jadx" },
    );
    expect(findings).toHaveLength(0);
  });
});

describe("Prompt 17 correlation + gate (§51/§52/§88/§90)", () => {
  it("cross-build identity is stable across builds; per-build identity is not (§51)", () => {
    const parts = { applicationRef: "com.example.app", platform: "ANDROID", component: "network-security-config", ruleId: "MOBILE_CLEARTEXT_ENABLED", cwe: "CWE-319", findingType: "MOBILE_NETWORK_FINDING" };
    const b1 = mobileFindingFingerprint({ ...parts, buildHash: "a".repeat(64) });
    const b2 = mobileFindingFingerprint({ ...parts, buildHash: "b".repeat(64) });
    expect(b1).not.toBe(b2);
    expect(mobileCrossBuildKey(parts)).toBe(mobileCrossBuildKey(parts));
  });

  it("static + dynamic observations of cleartext converge; dynamic confirms static (§52/§88)", () => {
    const base = [
      { title: "cleartext", description: "", severity: "HIGH" as const, confidence: 0.8, references: [], sourceTool: "mobile-platform-analysis", sourceFingerprint: "x1", ruleId: "MOBILE_CLEARTEXT_ENABLED", cwe: "CWE-319", mobileFindingType: "MOBILE_NETWORK_FINDING" as const, mobileComponent: "network-security-config" },
      { title: "cleartext dup", description: "", severity: "HIGH" as const, confidence: 0.8, references: [], sourceTool: "mobsf", sourceFingerprint: "x2", ruleId: "MOBILE_CLEARTEXT_ENABLED", cwe: "CWE-319", mobileFindingType: "MOBILE_NETWORK_FINDING" as const, mobileComponent: "network-security-config" },
      { title: "runtime", description: "", severity: "HIGH" as const, confidence: 0.95, references: [], sourceTool: "mitmproxy", sourceFingerprint: "x3", ruleId: "MOBILE_RUNTIME_CLEARTEXT_TRAFFIC", cwe: "CWE-319", mobileFindingType: "MOBILE_RUNTIME_FINDING" as const, host: "api.example.com" },
    ];
    const merged = correlateMobileFindings(base as never, IDENTITY);
    const cleartext = merged.filter((f) => f.ruleId === "MOBILE_CLEARTEXT_ENABLED");
    expect(cleartext).toHaveLength(1); // MobSF + platform → ONE canonical (§52)
    expect(cleartext[0]?.dynamicConfirmed).toBe(true); // §88
    expect(canonicalMobileFingerprint(base[0] as never, IDENTITY)).toBe(cleartext[0]?.sourceFingerprint);
    expect(crossBuildKeyFor(base[0] as never, IDENTITY)).toBe(cleartext[0]?.crossBuildFingerprint);
  });

  it("gate blocks on each §90 rule", () => {
    const clean = summarizeMobileForGate([]);
    expect(evaluateMobileSecurityGate(clean).status).toBe("PASSED");
    const dirty = summarizeMobileForGate([
      { severity: "HIGH", ruleId: "MOBILE_CLEARTEXT_ENABLED", mobileFindingType: "MOBILE_NETWORK_FINDING" },
      { severity: "HIGH", ruleId: "MOBILE_EXPORTED_COMPONENT_UNPROTECTED", mobileFindingType: "MOBILE_MISCONFIGURATION" },
    ]);
    const verdict = evaluateMobileSecurityGate(dirty);
    expect(verdict.status).toBe("FAILED");
    expect(verdict.failedRules).toContain("NO_CRITICAL_NETWORK_MISCONFIGURATION");
    expect(verdict.failedRules).toContain("NO_CRITICAL_EXPORTED_COMPONENT");
  });
});

describe("Prompt 17 instrumentation policy (§69–§75)", () => {
  const modules: InstrumentationModuleRecord[] = [
    { id: "mod-1", name: "runtime-config-observer", tool: "FRIDA", version: "1.0.0", moduleHash: "a".repeat(64), approved: true, status: "APPROVED" },
    { id: "mod-2", name: "unreviewed-module", tool: "FRIDA", version: "0.1.0", moduleHash: "b".repeat(64), approved: false, status: "REGISTERED" },
  ];
  const budget = { maxInstrumentationModules: 4 };

  it("Frida/Objection without approval are BLOCKED (§70/§74/§110)", () => {
    const decision = evaluateInstrumentationPolicy(
      { requestedActions: [], moduleIds: ["mod-1"], hasApprovedSession: true, hasInstrumentationApproval: false, killSwitchActive: false },
      modules, budget,
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reasons.join(" ")).toMatch(/NO_INSTRUMENTATION_APPROVAL/);
  });

  it("an approved session + approved module is eligible (§73)", () => {
    const decision = evaluateInstrumentationPolicy(
      { requestedActions: ["RUNTIME_CONFIG_OBSERVATION"], moduleIds: ["mod-1"], hasApprovedSession: true, hasInstrumentationApproval: true, killSwitchActive: false },
      modules, budget,
    );
    expect(decision.allowed).toBe(true);
  });

  it("arbitrary scripts, shell commands and prohibited actions refuse everything (§59/§72/§75/§111)", () => {
    for (const req of [
      { requestedActions: [], scriptBody: "Java.perform(function(){})", moduleIds: ["mod-1"], hasApprovedSession: true, hasInstrumentationApproval: true, killSwitchActive: false },
      { requestedActions: [], shellCommand: "adb shell id", moduleIds: ["mod-1"], hasApprovedSession: true, hasInstrumentationApproval: true, killSwitchActive: false },
      { requestedActions: ["CREDENTIAL_THEFT"], moduleIds: ["mod-1"], hasApprovedSession: true, hasInstrumentationApproval: true, killSwitchActive: false },
      { requestedActions: [], moduleIds: ["mod-2"], hasApprovedSession: true, hasInstrumentationApproval: true, killSwitchActive: false },
    ]) {
      expect(evaluateInstrumentationPolicy(req, modules, budget).allowed).toBe(false);
    }
    expect(PROHIBITED_MOBILE_AUTOMATION).toContain("ARBITRARY_ADB_SHELL");
    expect(PROHIBITED_MOBILE_AUTOMATION).toContain("SMS_INTERCEPTION");
  });

  it("an active kill switch blocks instrumentation (§92)", () => {
    const decision = evaluateInstrumentationPolicy(
      { requestedActions: [], moduleIds: ["mod-1"], hasApprovedSession: true, hasInstrumentationApproval: true, killSwitchActive: true },
      modules, budget,
    );
    expect(decision.allowed).toBe(false);
    expect(decision.reasons.join(" ")).toMatch(/KILL_SWITCH_ACTIVE/);
  });
});

describe("Prompt 17 adapters + health (§10/§16/§102)", () => {
  it("fixture health: CLI adapters HEALTHY with fixtures, connectors NOT_CONFIGURED, Frida/Objection governed", async () => {
    const runner = new FixtureToolRunner({
      jadx: { stdout: FIXTURE_JADX_OUTPUT, version: "1.5.1" },
      apktool: { stdout: FIXTURE_APKTOOL_OUTPUT, version: "2.9.3" },
      analyzeHeadless: { stdout: FIXTURE_GHIDRA_REPORT, version: "11.3" },
    });
    const adapters = createMobileAdapters(runner, createFixtureMobileDeps());
    const health = mobileHealthBySlug(adapters, createFixtureMobileDeps());
    expect(health.jadx).toBe("HEALTHY");
    expect(health.mobsf).toBe("UNKNOWN"); // transport wired in fixture deps
    expect(health.frida).toBe("DISABLED");
    expect(health.objection).toBe("APPROVAL_REQUIRED");
    expect(MOBILE_DISABLED_REGISTRATIONS.map((r) => r.slug)).toEqual(["frida", "objection"]);
    // No adapter exists for the disabled registrations.
    expect(adapters.map((a) => a.metadata.slug)).not.toContain("frida");
    expect(adapters.map((a) => a.metadata.slug)).not.toContain("objection");
  });

  it("the MobSF connector refuses without a registered instance (§14)", async () => {
    const adapters = createMobileAdapters(new FixtureToolRunner({}), createFixtureMobileDeps());
    const mobsf = adapters.find((a) => a.metadata.slug === "mobsf")!;
    await mobsf.buildExecutionPlan({ type: "MOBILE_APP", value: "com.example.app", host: "com.example.app" }, {
      mobileBuildId: FIXTURE_MOBILE_BUILD_RECORD.id, mobileBuildHash: FIXTURE_BUILD_HASH,
      mobileApplicationRef: "com.example.app", mobilePlatform: "ANDROID",
    });
    await expect(mobsf.execute({} as never)).rejects.toThrow(/NOT_CONFIGURED/);
  });

  it("the sha256 helper matches node crypto", () => {
    const bytes = new TextEncoder().encode("abc");
    expect(sha256Hex(bytes)).toBe(createHash("sha256").update(bytes).digest("hex"));
  });

  it("platform extraction composes the registered artifacts (§6)", () => {
    const extracted = extractMobileArtifacts(fixtureAnalysisArtifacts(), {
      applicationId: "mobile-app-1", applicationRef: "com.example.app",
      buildId: "mobile-build-1", buildHash: FIXTURE_BUILD_HASH,
      platform: "ANDROID", environment: "PRODUCTION", toolSlug: "mobile-platform-analysis",
    });
    expect(extracted.data.permissions.some((p) => p.name.endsWith("CAMERA"))).toBe(true);
    expect(extracted.data.deepLinks.some((l) => l.host === "app.example.com")).toBe(true);
    expect(extracted.data.nativeLibraries.some((l) => l.path.endsWith("libexample.so"))).toBe(true);
    expect(extracted.data.signing.some((s) => s.debug === true)).toBe(true);
    expect(extracted.components.map((c) => c.name)).toEqual(expect.arrayContaining(["example-json-lib", "example-net-lib"]));
    expect(extracted.findings.some((f) => f.ruleId === "MOBILE_HARDCODED_SECRET")).toBe(true);
    // The planted FAKE secret value exists in NO extraction output.
    expect(JSON.stringify(extracted)).not.toContain(FIXTURE_SECRET_VALUE);
  });
});
