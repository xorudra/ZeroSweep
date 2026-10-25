/**
 * Prompt 17 — mobile adapters (§13–§19/§34/§53–§65).
 *
 * Static family (MOBILE_STATIC_ANALYSIS workers): the MobSF connector
 * (admin-registered instance only), JADX and apktool (sandboxed CLI —
 * decompiled output is an artifact, code is never executed), Ghidra
 * (headless static, administrator-approved scripts only).
 * Dynamic family (MOBILE_DYNAMIC_ANALYSIS workers): the ADB lab
 * adapter and the mitmproxy adapter — both inert without a wired lab
 * transport + an approved session. Frida/Objection have NO adapter
 * (§69–§74): they exist as governed registrations only.
 */
import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import type { ToolRunner } from "../recon/runner";
import { assertMobileConfig, MobileAdapterBase, mobConfigStr, type MobileAdapterParserContext } from "./mobile-adapter.base";
import { parseApktoolOutput, parseGhidraReport, parseJadxOutput, parseMitmproxyFlows, parseMobsfReport } from "./parsers-mobile";
import { emptyParsedMobile, INERT_MOBILE_DEPS, type MobileConnectorDeps, type ParsedMobile } from "./types";

function mobileMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "homepage" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "MOBILE",
    executionMode: "CONTAINER",
    riskLevel: "LOW",
    requiresApproval: false,
    supportedTargetTypes: ["MOBILE_APP", "APK"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 1800, maxTimeoutSeconds: 3600,
    resources: { cpu: "1", memory: "2Gi", timeoutSeconds: 1800 },
    requiredWorkerType: "MOBILE_STATIC_ANALYSIS",
    inputSchema: [
      { name: "mobileApplicationId", type: "string", description: "Registered MobileApplication id resolved by the worker from the scan target — never client-supplied" },
      { name: "mobileBuildId", type: "string", description: "Registered MobileBuild id — worker-derived" },
      { name: "mobileBuildHash", type: "string", description: "SHA-256 build identity — worker-derived from the build row (§5)" },
      { name: "mobileApplicationRef", type: "string", description: "Package name / bundle id (fingerprint component) — worker-derived" },
      { name: "mobilePlatform", type: "string", description: "ANDROID | IOS — worker-derived" },
      { name: "mobileArtifactReference", type: "string", description: "Object-storage reference of the uploaded artifact — worker-derived; the artifact is mounted read-only in the sandbox (§8)" },
    ],
    ...partial,
  } as ToolMetadata;
}

// ── MobSF connector (§13–§17) ──────────────────────────────────────

export class MobSFConnectorAdapter extends BaseSecurityToolAdapter {
  readonly metadata = mobileMeta({
    id: "mobsf", slug: "mobsf", name: "MobSF",
    description: "MobSF static-analysis connector (§13–§17): submits ONLY authorized artifacts to the administrator-registered trusted instance and normalizes its report (severity/title/file/CWE/OWASP Mobile/MASVS). Credentials are secret references on the ScannerInstance (§14). Dynamic MobSF capabilities are classified separately and never run by this connector.",
    homepage: "https://mobsf.github.io/Mobile-Security-Framework-MobSF/",
    licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API",
    capabilities: ["MOBILE_STATIC_ANALYSIS", "MANIFEST_ANALYSIS", "CODE_ANALYSIS", "BINARY_ANALYSIS", "CERTIFICATE_ANALYSIS", "NETWORK_SECURITY_CONFIG_ANALYSIS"],
    // Like the other scanner connectors (ZAP/Burp), the instance
    // credential is a secret reference ON the ScannerInstance row,
    // resolved inside the worker boundary by instance id — the tool
    // policy never sees a credential name (§14).
    requiresCredentials: [],
    inputSchema: [
      { name: "mobileBuildId", type: "string", description: "Registered MobileBuild id — worker-derived" },
      { name: "mobileBuildHash", type: "string", description: "SHA-256 build identity — the ONLY artifact key the instance is queried with (§15)" },
      { name: "mobileApplicationRef", type: "string", description: "Package name / bundle id — worker-derived" },
      { name: "mobilePlatform", type: "string", description: "ANDROID | IOS — worker-derived" },
      { name: "mobileScannerInstanceId", type: "string", description: "Admin-registered ScannerInstance id — resolved by the worker from trusted rows, never client-supplied (§14)" },
    ],
  });

  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  constructor(private readonly deps: MobileConnectorDeps = INERT_MOBILE_DEPS) { super(); }

  async checkAvailability(): Promise<boolean> { return true; } // per-instance state resolves at execute time

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: "MobSF health is per-instance: NOT_CONFIGURED until an administrator registers a ScannerInstance (§14)" };
  }

  async buildExecutionPlan(_target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "EXTERNAL_API",
      arguments: [], environmentReferences: [],
      timeoutSeconds: this.metadata.defaultTimeoutSeconds,
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError("mobsf: execute() called without buildExecutionPlan()");
    if (!mobConfigStr(config, "mobileScannerInstanceId")) {
      throw new AdapterUnavailableError("mobsf: no MobSF ScannerInstance is registered for this workspace — connector reports NOT_CONFIGURED (§14)");
    }
    const buildHash = mobConfigStr(config, "mobileBuildHash");
    if (!buildHash) throw new AdapterUnavailableError("mobsf: no build is registered for this scan — NOT_CONFIGURED");
    const transport = this.deps.transports.mobsf;
    if (!transport) {
      throw new AdapterUnavailableError("mobsf: no MobSF transport is configured in this worker — instance reports NOT_CONFIGURED (§16)");
    }
    const report = await transport.fetchReport(buildHash);
    if (!report) {
      throw new AdapterUnavailableError(`mobsf: the configured instance holds no report for build ${buildHash.slice(0, 12)}… — NOT_CONFIGURED for this build (§15)`);
    }
    this.lastRaw = report;
    return { rawOutput: report };
  }

  async parse(raw: string): Promise<ParsedMobile> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedMobile();
    const c = this.pendingConfig ?? {};
    return parseMobsfReport(text, {
      toolSlug: this.metadata.slug,
      applicationRef: mobConfigStr(c, "mobileApplicationRef") ?? "unknown-app",
      platform: mobConfigStr(c, "mobilePlatform") === "IOS" ? "IOS" : "ANDROID",
      buildHash: mobConfigStr(c, "mobileBuildHash") ?? "unknown-build",
    });
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedMobile;
    const endpoints = (p.mobile?.endpoints ?? []).map((e) => ({
      url: e.url, method: "GET", source: this.metadata.slug, sources: [this.metadata.slug],
    }));
    return {
      assets: [], services: [], endpoints, technologies: [],
      findings: p.findings ?? [],
      ...(p.mobile ? { mobile: p.mobile } : {}),
      artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertMobileConfig(config);
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

// ── JADX (§19) ─────────────────────────────────────────────────────

export class JadxAdapter extends MobileAdapterBase {
  readonly metadata = mobileMeta({
    id: "jadx", slug: "jadx", name: "JADX",
    description: "JADX Android decompilation (§19): runs in the static sandbox and emits decompiled-source inventory. The output is an analysis artifact — decompiled code is NEVER executed, and access to it is RBAC-gated because it may contain credentials/PII (§24).",
    homepage: "https://github.com/skylot/jadx", licenseType: "OPEN_SOURCE",
    capabilities: ["ANDROID_DECOMPILATION", "STATIC_CODE_EXTRACTION"],
  });
  readonly executable = "jadx";
  readonly containerImage = "jadx:latest";
  readonly versionArgs = ["--version"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected mobilePlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const artifact = mobConfigStr(config, "mobileArtifactReference") ?? "";
    // Governed invocation: decompile to the sandbox workspace, emit the
    // structured summary the parser consumes. No code execution flags
    // exist in this invocation (§19).
    return { args: ["--no-res", "--no-debug-info", "--output-format", "json-summary", artifact] };
  }

  protected parseMobile(text: string, ctx: MobileAdapterParserContext): ParsedMobile {
    return parseJadxOutput(text, ctx);
  }
}

// ── apktool (§18) ──────────────────────────────────────────────────

export class ApktoolAdapter extends MobileAdapterBase {
  readonly metadata = mobileMeta({
    id: "apktool", slug: "apktool", name: "apktool",
    description: "apktool APK resource analysis (§18): manifest + resource extraction in the tool's safe workspace. ZeroSweep consumes the decoded manifest text and file inventory — extracted binaries are never executed (§8).",
    homepage: "https://apktool.org", licenseType: "OPEN_SOURCE",
    capabilities: ["APK_RESOURCE_ANALYSIS", "MANIFEST_EXTRACTION", "RESOURCE_EXTRACTION"],
  });
  readonly executable = "apktool";
  readonly containerImage = "apktool:latest";
  readonly versionArgs = ["--version"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected mobilePlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const artifact = mobConfigStr(config, "mobileArtifactReference") ?? "";
    return { args: ["d", "--no-src", "--output-format", "json-summary", artifact] };
  }

  protected parseMobile(text: string, ctx: MobileAdapterParserContext): ParsedMobile {
    return parseApktoolOutput(text, ctx);
  }
}

// ── Ghidra (§34–§36) ───────────────────────────────────────────────

export class GhidraAdapter extends MobileAdapterBase {
  readonly metadata = mobileMeta({
    id: "ghidra", slug: "ghidra", name: "Ghidra (headless, static)",
    description: "Ghidra headless binary static analysis (§34–§36): native-library inventory + hardening properties (PIE/NX/canaries/RELRO/symbols). Headless/static only — native binaries are never executed, and only administrator-approved analysis scripts may run (§35): the script is a governed platform constant, never user input.",
    homepage: "https://ghidra-sre.org", licenseType: "OPEN_SOURCE",
    riskLevel: "MODERATE",
    requiresApproval: true,
    capabilities: ["BINARY_STATIC_ANALYSIS", "NATIVE_LIBRARY_ANALYSIS"],
  });
  readonly executable = "analyzeHeadless";
  readonly containerImage = "ghidra:latest";
  readonly versionArgs = ["-version"];

  constructor(runner?: ToolRunner) { super(runner); }

  protected mobilePlan(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const artifact = mobConfigStr(config, "mobileArtifactReference") ?? "";
    // §35: the ONLY script is the platform's approved, versioned
    // inventory script. There is no config field that could name a
    // different one (assertMobileConfig refuses script keys).
    return { args: ["MobileSandbox", "MobileInventory", "-import", artifact, "-scriptPath", "/opt/zerosweep/ghidra-scripts", "-postScript", "MobileHardeningInventory.py", "-deleteProject"] };
  }

  protected parseMobile(text: string, ctx: MobileAdapterParserContext): ParsedMobile {
    return parseGhidraReport(text, ctx);
  }
}

// ── ADB lab adapter (§53–§61) ──────────────────────────────────────

export class AdbLabAdapter extends BaseSecurityToolAdapter {
  readonly metadata = mobileMeta({
    id: "adb", slug: "adb", name: "ADB (device lab)",
    description: "ADB device-lab adapter (§53–§61): governed operations on ZeroSweep-managed approved lab devices ONLY — install the authorized build (hash verified first, §60), collect logs, reset the device. There is NO generic adb shell operation anywhere (§59/§75). Personal devices are never targeted (§55).",
    homepage: "https://developer.android.com/tools/adb", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API",
    riskLevel: "MODERATE",
    requiresApproval: true,
    requiredWorkerType: "MOBILE_DYNAMIC_ANALYSIS",
    capabilities: ["DEVICE_MANAGEMENT", "APP_INSTALLATION", "LOG_COLLECTION", "CONTROLLED_APP_INTERACTION"],
    supportedTargetTypes: ["MOBILE_APP", "APK"],
    inputSchema: [
      { name: "mobileApplicationId", type: "string", description: "Registered MobileApplication id — worker-derived" },
      { name: "mobileBuildId", type: "string", description: "Registered MobileBuild id — worker-derived" },
      { name: "mobileBuildHash", type: "string", description: "SHA-256 verified before any install (§60) — worker-derived" },
      { name: "mobileDeviceId", type: "string", description: "Approved lab device id — worker-derived from the session record" },
      { name: "mobileDynamicSessionId", type: "string", description: "Approved dynamic session id — worker-derived (§73)" },
      { name: "mobileApplicationRef", type: "string", description: "Package name / bundle id — worker-derived" },
      { name: "mobilePlatform", type: "string", description: "ANDROID | IOS — worker-derived" },
    ],
  });

  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  constructor(private readonly deps: MobileConnectorDeps = INERT_MOBILE_DEPS) { super(); }

  async checkAvailability(): Promise<boolean> { return true; }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: "ADB lab health is per-lab: NOT_CONFIGURED until a device-lab transport is wired in a MOBILE_DYNAMIC_ANALYSIS worker (§53)" };
  }

  async buildExecutionPlan(_target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "EXTERNAL_API",
      arguments: [], environmentReferences: [],
      timeoutSeconds: this.metadata.defaultTimeoutSeconds,
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError("adb: execute() called without buildExecutionPlan()");
    if (!mobConfigStr(config, "mobileDynamicSessionId")) {
      throw new AdapterUnavailableError("adb: no APPROVED dynamic session exists for this execution — the lab refuses (§58/§73)");
    }
    const transport = this.deps.transports.devices;
    if (!transport) {
      throw new AdapterUnavailableError("adb: no device-lab transport is configured in this worker — lab reports NOT_CONFIGURED (§53)");
    }
    const deviceId = mobConfigStr(config, "mobileDeviceId");
    const buildHash = mobConfigStr(config, "mobileBuildHash");
    if (!deviceId || !buildHash) throw new AdapterUnavailableError("adb: session lacks a device or build — NOT_CONFIGURED");
    const install = await transport.installApprovedBuild(deviceId, buildHash);
    if (!install.verifiedHash || !install.installed) {
      throw new AdapterUnavailableError("adb: build hash verification failed before install — install refused (§60)");
    }
    const payload = { installed: true, verifiedHash: true, deviceId };
    this.lastRaw = JSON.stringify(payload);
    return { rawOutput: this.lastRaw };
  }

  async parse(raw: string): Promise<ParsedMobile> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedMobile();
    try {
      const rec = JSON.parse(text) as Record<string, unknown>;
      return emptyParsedMobile({ installed: rec.installed ? 1 : 0, hashVerified: rec.verifiedHash ? 1 : 0 });
    } catch { return emptyParsedMobile({ parseErrors: 1 }); }
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedMobile;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: [], artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertMobileConfig(config);
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

// ── mitmproxy lab adapter (§62–§68) ────────────────────────────────

export class MitmproxyAdapter extends BaseSecurityToolAdapter {
  readonly metadata = mobileMeta({
    id: "mitmproxy", slug: "mitmproxy", name: "mitmproxy (traffic lab)",
    description: "mitmproxy traffic-lab adapter (§62–§68): reads a COMPLETED lab capture's sanitized flow metadata (hosts/methods/paths/status/TLS) and discovers API endpoints as DISCOVERED_REFERENCEs. TLS interception exists only inside the lab with a temporary CA that is removed after testing (§67); raw bodies never enter platform records (§66).",
    homepage: "https://mitmproxy.org", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API",
    riskLevel: "MODERATE",
    requiresApproval: true,
    requiredWorkerType: "MOBILE_DYNAMIC_ANALYSIS",
    capabilities: ["MOBILE_TRAFFIC_CAPTURE", "HTTP_ANALYSIS", "API_DISCOVERY"],
    supportedTargetTypes: ["MOBILE_APP", "APK"],
    inputSchema: [
      { name: "mobileBuildId", type: "string", description: "Registered MobileBuild id — worker-derived" },
      { name: "mobileBuildHash", type: "string", description: "SHA-256 build identity — worker-derived" },
      { name: "mobileTrafficSessionId", type: "string", description: "Approved traffic session id — worker-derived from the session record (§64)" },
      { name: "mobileApplicationRef", type: "string", description: "Package name / bundle id — worker-derived" },
      { name: "mobilePlatform", type: "string", description: "ANDROID | IOS — worker-derived" },
    ],
  });

  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  constructor(private readonly deps: MobileConnectorDeps = INERT_MOBILE_DEPS) { super(); }

  async checkAvailability(): Promise<boolean> { return true; }

  async healthCheck(): Promise<{ status: string; detail?: string }> {
    return { status: "UNKNOWN", detail: "mitmproxy health is per-lab: NOT_CONFIGURED until a traffic-lab transport is wired in a MOBILE_DYNAMIC_ANALYSIS worker (§62)" };
  }

  async buildExecutionPlan(_target: AdapterTarget, config: Record<string, unknown>): Promise<ExecutionPlan> {
    await this.validateConfiguration(config);
    return {
      adapterId: this.metadata.id, toolId: this.metadata.id, executionMode: "EXTERNAL_API",
      arguments: [], environmentReferences: [],
      timeoutSeconds: this.metadata.defaultTimeoutSeconds,
      cpuLimit: this.metadata.resources.cpu, memoryLimit: this.metadata.resources.memory,
      networkPolicy: "CUSTOM_ALLOWLIST", expectedOutputFormat: "JSON", outputFiles: [],
    };
  }

  async execute(_plan: ExecutionPlan): Promise<{ rawOutputLocation?: string; rawOutput?: string }> {
    const config = this.pendingConfig;
    if (!config) throw new AdapterConfigurationError("mitmproxy: execute() called without buildExecutionPlan()");
    const sessionId = mobConfigStr(config, "mobileTrafficSessionId");
    if (!sessionId) {
      throw new AdapterUnavailableError("mitmproxy: no APPROVED traffic session exists for this execution — capture refuses (§64)");
    }
    const transport = this.deps.transports.traffic;
    if (!transport) {
      throw new AdapterUnavailableError("mitmproxy: no traffic-lab transport is configured in this worker — lab reports NOT_CONFIGURED (§62)");
    }
    const flows = await transport.readSession(sessionId);
    if (!flows) throw new AdapterUnavailableError(`mitmproxy: no completed capture exists for session ${sessionId} — NOT_CONFIGURED`);
    this.lastRaw = flows;
    return { rawOutput: flows };
  }

  async parse(raw: string): Promise<ParsedMobile> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedMobile();
    const c = this.pendingConfig ?? {};
    return parseMitmproxyFlows(text, {
      toolSlug: this.metadata.slug,
      applicationRef: mobConfigStr(c, "mobileApplicationRef") ?? "unknown-app",
      platform: mobConfigStr(c, "mobilePlatform") === "IOS" ? "IOS" : "ANDROID",
      buildHash: mobConfigStr(c, "mobileBuildHash") ?? "unknown-build",
    });
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedMobile;
    const endpoints = (p.mobile?.endpoints ?? []).map((e) => ({
      url: e.url, method: "GET", source: this.metadata.slug, sources: [this.metadata.slug],
    }));
    return {
      assets: [], services: [], endpoints, technologies: [],
      findings: p.findings ?? [],
      ...(p.mobile ? { mobile: p.mobile } : {}),
      artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertMobileConfig(config);
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

export const MOBILE_STATIC_SLUGS = ["mobsf", "jadx", "apktool", "ghidra"] as const;
export const MOBILE_DYNAMIC_SLUGS = ["adb", "mitmproxy"] as const;
export const MOBILE_SLUGS = [...MOBILE_STATIC_SLUGS, ...MOBILE_DYNAMIC_SLUGS] as const;
