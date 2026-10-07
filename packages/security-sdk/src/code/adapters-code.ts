import { BaseSecurityToolAdapter } from "../adapter/adapter.base";
import { AdapterConfigurationError, AdapterUnavailableError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import type { ToolMetadata } from "../adapter/adapter.types";
import type { ExecutionPlan } from "../execution/execution.types";
import type { NormalizedSecurityResult } from "../findings/finding.types";
import type { ConnectorDeps } from "../proxy/connector";
import { assertScannerEndpointAllowed } from "../proxy/connector";
import type { ScannerInstanceRecord } from "../proxy/types";
import type { ReconPlanParts } from "../recon/recon-adapter.base";
import { CodeAdapterBase } from "./code-adapter.base";
import {
  emptyParsedCode, importSarif, parseBandit, parseBrakeman, parseDependencyCheck,
  parseGitleaks, parseGrype, parseSemgrep, parseSonarIssues, parseSpotbugs,
  parseTrufflehog, type ParsedCode,
} from "./parsers-code";
import { resolveCodeqlPlan, resolveSemgrepPacks } from "./policies";

/**
 * Source-code tool adapters (Prompt 12 §21–§53). Every adapter:
 *  - analyzes a snapshot PATH read-only (DO_NOT_EXECUTE_SOURCE, §14);
 *  - runs with network policy NO_NETWORK (§13) — databases and rule
 *    packs are provisioned on the worker, never fetched per scan;
 *  - builds its command ONLY from validated, adapter-declared fields —
 *    there is no raw-argument or arbitrary-rule surface (§22/§30);
 *  - reports health honestly: no binary on PATH = UNAVAILABLE.
 */

function codeMeta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "homepage" | "licenseType" | "capabilities">): ToolMetadata {
  return {
    adapterVersion: "1.0.0",
    category: "SOURCE_CODE",
    executionMode: "CONTAINER",
    riskLevel: "LOW",
    requiresApproval: false,
    supportedTargetTypes: ["SOURCE_REPOSITORY"],
    supportedOutputFormats: ["JSON"],
    requiresCredentials: [],
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 1800, maxTimeoutSeconds: 3600,
    resources: { cpu: "2", memory: "2Gi", timeoutSeconds: 1800 },
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path resolved by the worker from the scan's immutable snapshot (§5) — never client-supplied" },
      { name: "repositoryId", type: "string", description: "Repository identity used for line-stable source fingerprints (§64)" },
      { name: "languages", type: "string[]", description: "Detected snapshot languages (worker-derived from the LANGUAGE_DETECTION stage)" },
      { name: "excludePatterns", type: "string[]", description: "Governed exclusion patterns from the source exclusion policy (§85)" },
    ],
    ...partial,
  } as ToolMetadata;
}

function stringList(config: Record<string, unknown>, key: string): string[] {
  return Array.isArray(config[key]) ? (config[key] as unknown[]).filter((x): x is string => typeof x === "string") : [];
}

// ── Semgrep (§21/§22) ─────────────────────────────────────────────────

export class SemgrepAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "semgrep", slug: "semgrep", name: "Semgrep",
    description: "Pattern-based SAST over the governed, pinned rule-pack catalog (§22): packs are selected by policy from detected languages — users can never supply arbitrary rule paths or rule content.",
    homepage: "https://semgrep.dev", licenseType: "OPEN_SOURCE",
    capabilities: ["SAST", "CODE_PATTERN_ANALYSIS", "SECURITY_RULE_ANALYSIS", "DATAFLOW_ANALYSIS"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path (worker-resolved)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
      { name: "languages", type: "string[]", description: "Detected languages (worker-derived)" },
      { name: "rulePacks", type: "string[]", description: "Governed pack ids resolved by the SemgrepRulePolicy in the worker — catalog ids only" },
      { name: "excludePatterns", type: "string[]", description: "Governed exclusion patterns (§85)" },
    ],
  });
  readonly executable = "semgrep";
  readonly containerImage = "semgrep/semgrep:latest";
  readonly versionArgs = ["--version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const sourcePath = this.sourcePath(target, config);
    let packs = stringList(config, "rulePacks");
    if (packs.length === 0) {
      packs = resolveSemgrepPacks({ profile: "SOURCE_BASELINE", languages: stringList(config, "languages") }).packs;
    }
    return {
      args: [
        "scan", "--json", "--metrics=off", "--disable-version-check", "--quiet",
        ...packs.flatMap((p) => ["--config", p]),
        ...stringList(config, "excludePatterns").flatMap((p) => ["--exclude", p]),
        sourcePath,
      ],
    };
  }

  protected parseCode(text: string): ParsedCode { return parseSemgrep(text, this.parserContext()); }
}

// ── CodeQL (§28–§30) ──────────────────────────────────────────────────

export class CodeqlAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "codeql", slug: "codeql", name: "CodeQL",
    description: "Semantic SAST with governed, pinned query suites (§30) and SARIF import (§31). Languages that cannot be extracted without building the target are marked BUILD_REQUIRED — the platform never builds target code (§14/§29).",
    homepage: "https://codeql.github.com", licenseType: "OPEN_SOURCE",
    capabilities: ["SAST", "SECURITY_QUERY_ANALYSIS", "DATAFLOW_ANALYSIS"],
    supportedOutputFormats: ["SARIF"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path (worker-resolved)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
      { name: "languages", type: "string[]", description: "Detected languages (worker-derived)" },
      { name: "excludePatterns", type: "string[]", description: "Governed exclusion patterns (§85)" },
      { name: "codeqlDatabasePath", type: "string", description: "Worker-managed CodeQL database path for the snapshot (created with --build-mode=none)" },
    ],
  });
  readonly executable = "codeql";
  readonly containerImage = "ghcr.io/github/codeql-cli/codeql-bundle:latest";
  readonly versionArgs = ["version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const languages = stringList(config, "languages");
    const resolved = resolveCodeqlPlan(languages);
    if (resolved.languages.length === 0) {
      const why = resolved.buildRequired.length > 0
        ? `BUILD_REQUIRED: ${resolved.buildRequired.join(", ")} cannot be extracted without building the target, which the repository execution policy forbids (§14/§29)`
        : "no CodeQL-supported language was detected in this snapshot (§29)";
      throw new AdapterUnavailableError(`codeql: ${why}`);
    }
    const primary = resolved.languages[0];
    const sourcePath = this.sourcePath(target, config);
    const dbPath = typeof config.codeqlDatabasePath === "string" ? config.codeqlDatabasePath : `${sourcePath}/.dsrclone/codeql-db-${primary.language}`;
    return {
      args: ["database", "analyze", dbPath, primary.suite, "--format=sarif-latest", "--output=codeql-results.sarif"],
      outputFiles: ["codeql-results.sarif"],
    };
  }

  protected parseCode(text: string): ParsedCode { return importSarif(text, this.parserContext()); }
}

// ── Bandit (§25) ──────────────────────────────────────────────────────

export class BanditAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "bandit", slug: "bandit", name: "Bandit",
    description: "Python security linter (AST-based checks with CWE mappings from the tool itself, §25/§67).",
    homepage: "https://bandit.readthedocs.io", licenseType: "OPEN_SOURCE",
    capabilities: ["SAST", "PYTHON_SECURITY_ANALYSIS"],
  });
  readonly executable = "bandit";
  readonly containerImage = "ghcr.io/pycqa/bandit:latest";
  readonly versionArgs = ["--version"];
  /** Bandit exits 1 when it FINDS issues — a successful analysis (§38). */
  protected override readonly acceptableExitCodes: readonly number[] = [0, 1];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const sourcePath = this.sourcePath(target, config);
    const excludes = stringList(config, "excludePatterns");
    return { args: ["-r", sourcePath, "-f", "json", "-q", ...(excludes.length > 0 ? ["-x", excludes.join(",")] : [])] };
  }

  protected parseCode(text: string): ParsedCode { return parseBandit(text, this.parserContext()); }
}

// ── Brakeman (§26) ────────────────────────────────────────────────────

export class BrakemanAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "brakeman", slug: "brakeman", name: "Brakeman",
    description: "Ruby on Rails security scanner: framework-aware checks over Rails applications (§26). Runs read-only against the snapshot — the Rails app is never booted.",
    homepage: "https://brakemanscanner.org", licenseType: "OPEN_SOURCE",
    capabilities: ["SAST", "FRAMEWORK_SECURITY_ANALYSIS"],
  });
  readonly executable = "brakeman";
  readonly containerImage = "prescientsecurity/brakeman:latest";
  readonly versionArgs = ["--version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return { args: ["-f", "json", "--no-pager", "-q", this.sourcePath(target, config)] };
  }

  protected parseCode(text: string): ParsedCode { return parseBrakeman(text, this.parserContext()); }
}

// ── SpotBugs (§29) ────────────────────────────────────────────────────

export class SpotbugsAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "spotbugs", slug: "spotbugs", name: "SpotBugs + FindSecBugs",
    description: "Java bytecode analysis (§29): only SECURITY-category / FindSecBugs findings are imported — correctness bugs are not vulnerabilities. Requires compiled classes; the platform never builds target code, so unbuilt snapshots degrade honestly instead of inventing results.",
    homepage: "https://spotbugs.github.io", licenseType: "OPEN_SOURCE",
    capabilities: ["SAST"],
    supportedOutputFormats: ["XML"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path (worker-resolved)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
      { name: "languages", type: "string[]", description: "Detected languages (worker-derived)" },
      { name: "classesPath", type: "string", description: "Worker-resolved path of pre-built classes inside the snapshot, when the repository ships them" },
    ],
  });
  readonly executable = "spotbugs";
  readonly containerImage = "spotbugs/spotbugs:latest";
  readonly versionArgs = ["-version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const classesPath = typeof config.classesPath === "string" ? config.classesPath : `${this.sourcePath(target, config)}/build/classes`;
    return { args: ["-textui", "-xml:withMessages", "-low", classesPath] };
  }

  protected parseCode(text: string): ParsedCode { return parseSpotbugs(text, this.parserContext()); }
}

// ── Gitleaks (§34) ────────────────────────────────────────────────────

export class GitleaksAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "gitleaks", slug: "gitleaks", name: "Gitleaks",
    description: "Secret scanning over the snapshot and its bounded git history (§34). Matched values are fingerprinted at parse time and NEVER stored or displayed (§39–§41).",
    homepage: "https://gitleaks.io", licenseType: "OPEN_SOURCE",
    capabilities: ["SECRET_SCANNING", "SECRET_DETECTION"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path (worker-resolved)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
      { name: "languages", type: "string[]", description: "Detected languages (worker-derived)" },
      { name: "excludePatterns", type: "string[]", description: "Governed exclusion patterns (§85)" },
      { name: "historyDepth", type: "number", description: "Bounded history depth from the source scan budget (§83)" },
    ],
  });
  readonly executable = "gitleaks";
  readonly containerImage = "zricethezav/gitleaks:latest";
  readonly versionArgs = ["version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return {
      args: [
        "detect", "--source", this.sourcePath(target, config),
        "--report-format", "json", "--report-path", "/dev/stdout",
        "--no-banner", "--exit-code", "0",
      ],
    };
  }

  protected parseCode(text: string): ParsedCode { return parseGitleaks(text, this.parserContext()); }
}

// ── TruffleHog (§37) ──────────────────────────────────────────────────

export class TrufflehogAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "trufflehog", slug: "trufflehog", name: "TruffleHog",
    description: "High-entropy + known-format secret scanning (§37). External secret VERIFICATION IS DISABLED by platform policy (§44): the adapter always runs --no-verification and rejects any configuration that tries to enable it.",
    homepage: "https://trufflesecurity.com", licenseType: "OPEN_SOURCE",
    capabilities: ["SECRET_SCANNING", "SECRET_DETECTION", "SECRET_VERIFICATION"],
    supportedOutputFormats: ["JSONL"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path (worker-resolved)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
      { name: "languages", type: "string[]", description: "Detected languages (worker-derived)" },
      { name: "excludePatterns", type: "string[]", description: "Governed exclusion patterns (§85)" },
      { name: "externalVerification", type: "boolean", description: "MUST stay false — external verification contacts third-party services with candidate secrets and is forbidden by policy (§37/§44)" },
    ],
  });
  readonly executable = "trufflehog";
  readonly containerImage = "trufflesecurity/trufflehog:latest";
  readonly versionArgs = ["--version"];

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    if (config.externalVerification === true) {
      throw new AdapterConfigurationError("trufflehog: external secret verification is disabled by platform policy (§37/§44) and cannot be enabled through scan configuration");
    }
    await super.validateConfiguration(config);
  }

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return { args: ["filesystem", this.sourcePath(target, config), "--json", "--no-verification", "--no-update"] };
  }

  protected parseCode(text: string): ParsedCode { return parseTrufflehog(text, this.parserContext()); }
}

// ── OWASP Dependency-Check (§49) ──────────────────────────────────────

export class DependencyCheckAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "owasp-dependency-check", slug: "owasp-dependency-check", name: "OWASP Dependency-Check",
    description: "Dependency vulnerability analysis (§49) against the worker-provisioned vulnerability database (managed outside scans, §50). All network-using audits are disabled: no package is ever installed or fetched (§57).",
    homepage: "https://owasp.org/www-project-dependency-check/", licenseType: "OPEN_SOURCE",
    capabilities: ["SCA", "DEPENDENCY_VULNERABILITY_ANALYSIS"],
  });
  readonly executable = "dependency-check";
  readonly containerImage = "owasp/dependency-check:latest";
  readonly versionArgs = ["--version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    return {
      args: [
        "--scan", this.sourcePath(target, config), "--format", "JSON", "--out", ".",
        "--disableYarnAudit", "--disableNodeAudit", "--disableRetireJS", "--disableAssembly", "--disableBundleAudit",
      ],
      outputFiles: ["dependency-check-report.json"],
    };
  }

  protected parseCode(text: string): ParsedCode { return parseDependencyCheck(text, this.parserContext()); }
}

// ── Grype (§51) ───────────────────────────────────────────────────────

export class GrypeAdapter extends CodeAdapterBase {
  readonly metadata = codeMeta({
    id: "grype", slug: "grype", name: "Grype",
    description: "Package vulnerability scanning (§51) over the snapshot directory or the generated SBOM, using the worker-provisioned vulnerability database (updated outside scans). Fixed versions come from the tool's trusted data only (§74).",
    homepage: "https://github.com/anchore/grype", licenseType: "OPEN_SOURCE",
    capabilities: ["SCA", "PACKAGE_VULNERABILITY_ANALYSIS", "SBOM_ANALYSIS"],
    inputSchema: [
      { name: "sourcePath", type: "string", description: "Snapshot workspace path (worker-resolved)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
      { name: "languages", type: "string[]", description: "Detected languages (worker-derived)" },
      { name: "excludePatterns", type: "string[]", description: "Governed exclusion patterns (§85)" },
      { name: "sbomRef", type: "string", description: "Optional SBOM artifact reference to scan instead of the directory (sbom: input)" },
    ],
  });
  readonly executable = "grype";
  readonly containerImage = "anchore/grype:latest";
  readonly versionArgs = ["version"];

  protected codePlan(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const source = typeof config.sbomRef === "string" && config.sbomRef.length > 0
      ? `sbom:${config.sbomRef}`
      : `dir:${this.sourcePath(target, config)}`;
    return { args: [source, "-o", "json"] };
  }

  protected parseCode(text: string): ParsedCode { return parseGrype(text, this.parserContext()); }
}

// ── SonarQube connector (§23–§27) ─────────────────────────────────────

/**
 * SonarQube is an administrator-managed SERVICE (§23): DSRclone reads
 * analysis results from the registered instance — it never submits
 * builds (the sonar-scanner flow needs target builds, §24/§29, which
 * the execution policy forbids). Unconfigured it reports NOT_CONFIGURED
 * honestly and the SAST stage degrades (§86 pattern).
 */
export class SonarQubeAdapter extends BaseSecurityToolAdapter {
  readonly metadata = codeMeta({
    id: "sonarqube", slug: "sonarqube", name: "SonarQube",
    description: "Administrator-managed code-quality/security platform (§23): vulnerabilities import as findings; SECURITY HOTSPOTS import as REVIEW_REQUIRED — never auto-promoted to vulnerabilities (§27); code smells are not vulnerabilities (§26). Unconfigured = NOT_CONFIGURED.",
    homepage: "https://www.sonarqube.org", licenseType: "OPEN_SOURCE",
    executionMode: "EXTERNAL_API",
    requiresApproval: true,
    requiresCredentials: ["SONAR_TOKEN"],
    supportsContainerExecution: false,
    capabilities: ["SAST", "CODE_PATTERN_ANALYSIS", "SCAN_RESULT_IMPORT"],
    inputSchema: [
      { name: "instanceId", type: "string", description: "Admin-registered SonarQube instance (worker-resolved from the workspace binding)" },
      { name: "sonarProjectKey", type: "string", description: "SonarQube project key for the repository (worker-derived from the repository record)" },
      { name: "repositoryId", type: "string", description: "Repository identity for fingerprints" },
    ],
  });

  private lastRaw = "";
  private pendingConfig: Record<string, unknown> | undefined;

  constructor(private readonly deps: ConnectorDeps) { super(); }

  private async instance(instanceId?: string): Promise<ScannerInstanceRecord | null> {
    if (instanceId) return this.deps.instances.getById(instanceId);
    const enabled = await this.deps.instances.listEnabled("SONARQUBE");
    return enabled[0] ?? null;
  }

  async checkAvailability(): Promise<boolean> {
    const instance = await this.instance();
    return !!instance && instance.enabled;
  }

  override async healthCheck(): Promise<{ status: string; detail?: string }> {
    const instance = await this.instance();
    if (!instance) {
      return { status: "NOT_CONFIGURED", detail: "No SonarQube instance is registered — an administrator must register one (§23). This is a configuration state, not a platform failure." };
    }
    try {
      const res = await this.call(instance, "/api/system/status");
      if (res.status >= 400) return { status: "UNAVAILABLE", detail: `SonarQube status endpoint returned ${res.status}` };
      return { status: "HEALTHY", detail: "SonarQube instance reachable" };
    } catch (err) {
      return { status: "UNAVAILABLE", detail: err instanceof Error ? err.message : String(err) };
    }
  }

  private async call(instance: ScannerInstanceRecord, path: string, query?: Record<string, string>) {
    const resolved = await this.deps.endpoints.resolve(instance.endpointReference);
    if (!resolved) throw new AdapterUnavailableError(`sonarqube: endpoint reference ${instance.endpointReference} is not configured on this host`);
    assertScannerEndpointAllowed(resolved.baseUrl, resolved.approvedInternal);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (instance.credentialReference) {
      const secret = await this.deps.secrets.resolve(instance.credentialReference);
      if (secret) headers.authorization = `Bearer ${secret}`;
    }
    return this.deps.transport.request({ baseUrl: resolved.baseUrl, approvedInternal: resolved.approvedInternal, request: { method: "GET", path, query, headers } });
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
    if (!config) throw new AdapterConfigurationError("sonarqube: execute() called without buildExecutionPlan()");
    const instanceId = typeof config.instanceId === "string" ? config.instanceId : undefined;
    if (!instanceId) throw new AdapterUnavailableError("sonarqube: no instance is configured for this workspace — connector reports NOT_CONFIGURED (§23)");
    const instance = await this.instance(instanceId);
    if (!instance) throw new AdapterUnavailableError(`sonarqube: instance ${instanceId} no longer exists`);
    const projectKey = typeof config.sonarProjectKey === "string" ? config.sonarProjectKey : "";
    if (!projectKey) throw new AdapterUnavailableError("sonarqube: no project key is mapped for this repository");
    const res = await this.call(instance, "/api/issues/search", {
      componentKeys: projectKey, types: "VULNERABILITY,SECURITY_HOTSPOT,CODE_SMELL,BUG", ps: "500",
    });
    if (res.status >= 400) throw new AdapterUnavailableError(`sonarqube: issue search returned ${res.status}`);
    this.lastRaw = res.body;
    return { rawOutput: this.lastRaw };
  }

  async parse(raw: string): Promise<ParsedCode> {
    const text = raw && raw.length > 0 ? raw : this.lastRaw;
    if (!text) return emptyParsedCode();
    return parseSonarIssues(text, {
      repositoryKey: typeof this.pendingConfig?.repositoryId === "string" ? this.pendingConfig.repositoryId : "repository",
      sourceTool: "sonarqube",
    });
  }

  async normalize(parsed: unknown): Promise<NormalizedSecurityResult> {
    const p = parsed as ParsedCode;
    return {
      assets: [], services: [], endpoints: [], technologies: [],
      findings: p.findings ?? [], components: p.components ?? [],
      artifacts: [], metrics: { ...(p.metrics ?? {}) }, mock: false,
    };
  }

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    await super.validateConfiguration(config);
    this.pendingConfig = config;
  }
}

/** Structural check used by the worker's stage executor (confinement):
 *  SonarQube executes through its connector lifecycle, never a runner. */
export function isSonarQubeAdapter(adapter: BaseSecurityToolAdapter): adapter is SonarQubeAdapter {
  return adapter instanceof SonarQubeAdapter;
}
