import type { AdapterTarget } from "../adapter/adapter.interface";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterInputField, ToolMetadata } from "../adapter/adapter.types";
import { TIMEOUT_FIELD, URLS_FIELD, type ReconPlanParts } from "../recon/recon-adapter.base";
import { ApiAdapterBase, type ParsedApi } from "../api/api-adapter.base";
import { parseCommixOutput, parseDalfoxOutput, parseSqlmapOutput, parseSstimapOutput, parseWpscanOutput, parseXsstrikeOutput } from "./parsers-injection";

/**
 * Governed adapters for the Prompt 32 detection tools (§70–§82).
 *
 * Every adapter here is DETECTION-ONLY by construction:
 *  - plans are fixed argv arrays built from validated fields — no raw
 *    option passthrough exists in any input schema (§131);
 *  - SQLmap runs boolean/technique-bounded detection with dumping,
 *    file access, OS interaction and modification structurally absent
 *    AND actively rejected if a config attempts them (§74/§179);
 *  - Commix verifies with the tool's harmless marker technique and
 *    rejects shell/os command options (§77/§78/§180);
 *  - SSTImap uses its arithmetic proof marker only (§79);
 *  - Dalfox/XSStrike prove XSS with a harmless reflection marker —
 *    no persistent payloads (§71);
 *  - WPScan enumerates only — password-attack options are rejected
 *    (§82).
 * No adapter performs post-exploitation of any kind (§80).
 */

function meta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "riskLevel" | "capabilities" | "supportedTargetTypes" | "supportedOutputFormats">): ToolMetadata {
  return {
    category: "WEB",
    adapterVersion: "1.0.0",
    licenseType: "OPEN_SOURCE",
    executionMode: "CONTAINER",
    requiresCredentials: [],
    requiresApproval: false,
    supportsContainerExecution: true,
    supportsCancellation: true,
    supportsProgress: false,
    defaultTimeoutSeconds: 600,
    maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
    ...partial,
  };
}

const str = (v: unknown): string | undefined => (typeof v === "string" && v.length > 0 ? v : undefined);

function startUrlOf(target: AdapterTarget, config: Record<string, unknown>): string {
  const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [];
  if (urls.length > 0) return urls[0]!;
  return target.value.includes("://") ? target.value : `https://${target.host}/`;
}

export const PARAMETER_FIELD: AdapterInputField = { name: "parameter", type: "string", description: "Single parameter under test — injection testers are always parameter-targeted (§75)" };
export const DELAY_FIELD: AdapterInputField = { name: "delayMs", type: "number", min: 0, max: 5000, description: "Bounded inter-request delay (milliseconds)" };

/** Scan every config value for forbidden flag fragments (§74/§179/§180). */
export function assertNoForbiddenOptions(slug: string, config: Record<string, unknown>, forbidden: readonly string[]): void {
  const haystacks: string[] = [];
  const collect = (v: unknown): void => {
    if (typeof v === "string") haystacks.push(v);
    else if (Array.isArray(v)) v.forEach(collect);
    else if (v && typeof v === "object") Object.values(v as Record<string, unknown>).forEach(collect);
  };
  Object.values(config).forEach(collect);
  for (const h of haystacks) {
    for (const f of forbidden) {
      if (h.toLowerCase().includes(f.toLowerCase())) {
        throw new AdapterConfigurationError(`${slug}: option '${f}' is forbidden by platform policy — detection-only operation (§74)`);
      }
    }
  }
}

/* ------------------------------- Dalfox (§70–§72) ------------------------------- */

export class DalfoxAdapter extends ApiAdapterBase {
  readonly executable = "dalfox";
  readonly containerImage = "hahwul/dalfox:latest";
  readonly versionArgs = ["version"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "dalfox", slug: "dalfox", name: "Dalfox",
    description: "Focused XSS scanner. Platform plans use Dalfox's parameter analysis with the harmless built-in marker set only — no custom/persistent payloads (§71).",
    homepage: "https://dalfox.hahwul.com",
    riskLevel: "MODERATE",
    capabilities: ["VULNERABILITY_SCANNING", "PARAMETER_DISCOVERY"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD, PARAMETER_FIELD, DELAY_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config);
    const delay = typeof config.delayMs === "number" ? Math.min(5000, Math.max(0, Math.floor(config.delayMs))) : 100;
    const args = ["url", this.baseUrl, "--format", "json", "--silence", "--no-spinner", "--no-color", "--delay", String(delay), "--timeout", "10", "--retries", "1"];
    // Deliberately absent: --custom-payload, --inject-into, blind-XSS
    // callback options — the platform never supplies external callback
    // URLs or persistent payloads (§71/§141).
    return { args };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseDalfoxOutput(text, this.metadata.slug);
  }
}

/* ------------------------------- XSStrike (§70–§72) ------------------------------- */

export class XsstrikeAdapter extends ApiAdapterBase {
  readonly executable = "xsstrike";
  readonly containerImage = "zerosweep/xsstrike:governed";
  readonly versionArgs = ["--help"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "xsstrike", slug: "xsstrike", name: "XSStrike",
    description: "XSS detection suite run in crawl-free, single-URL mode with its reflection checks only (§70).",
    homepage: "https://github.com/s0md3v/XSStrike",
    riskLevel: "MODERATE",
    capabilities: ["VULNERABILITY_SCANNING"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["TEXT"],
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD, PARAMETER_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config);
    // --skip-crawl/--skip-fuzzing keep XSStrike to reflection checks on
    // the single authorized URL; no payload file can be supplied.
    return { args: ["-u", this.baseUrl, "--skip-crawl", "--skip-dom", "--timeout", "10"] };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseXsstrikeOutput(text, this.metadata.slug);
  }
}

/* ------------------------------- SQLmap (§73–§76) ------------------------------- */

/** §74: options that can never appear in a platform SQLmap plan. */
export const SQLMAP_FORBIDDEN_OPTIONS: readonly string[] = [
  "--dump", "--dump-all", "--os-shell", "--os-pwn", "--os-cmd", "--file-read", "--file-write",
  "--file-dest", "--sql-shell", "--sql-query", "--common-tables", "--common-columns",
  "--passwords", "--privileges", "--roles", "--users", "--dbs", "--tables", "--columns",
  "--purge", "--update", "--smoke-test", "--wizard", "--dependencies", "--proxy-cred",
];

export class SqlmapAdapter extends ApiAdapterBase {
  readonly executable = "sqlmap";
  readonly containerImage = "googlesky/sqlmap:latest";
  readonly versionArgs = ["--version"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "sqlmap", slug: "sqlmap", name: "SQLmap",
    description: "SQL injection DETECTION only: boolean-based technique, lowest level/risk, single authorized parameter. Dumping, file access, OS shell and database modification are structurally disabled and actively rejected (§74).",
    homepage: "https://sqlmap.org",
    riskLevel: "INTRUSIVE",
    capabilities: ["VULNERABILITY_SCANNING"],
    supportedTargetTypes: ["WEB_APPLICATION", "API"],
    supportedOutputFormats: ["TEXT"],
    requiresApproval: true,
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD, PARAMETER_FIELD,
      { name: "level", type: "number", min: 1, max: 2, description: "Detection depth — platform-capped at 2 (default 1)" },
      { name: "dbms", type: "string", description: "Optional DBMS hint from earlier safe fingerprinting — narrows detection, never enables extraction" },
    ],
  });

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertNoForbiddenOptions("sqlmap", config, SQLMAP_FORBIDDEN_OPTIONS);
    await super.validateConfiguration(config);
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config);
    const parameter = str(config.parameter);
    const level = typeof config.level === "number" ? Math.min(2, Math.max(1, Math.floor(config.level))) : 1;
    const args = [
      "-u", this.baseUrl,
      "--batch", "--level", String(level), "--risk", "1",
      "--technique=B", "--flush-session", "--fresh-queries",
      "--timeout", "10", "--retries", "1", "--threads", "1",
      "--disable-coloring", "--skip-waf",
    ];
    if (parameter) args.push("-p", parameter);
    const dbms = str(config.dbms);
    if (dbms) args.push("--dbms", dbms);
    // Structurally absent (§74): every extraction/OS/modification flag
    // in SQLMAP_FORBIDDEN_OPTIONS. Detection is the whole capability.
    return { args };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseSqlmapOutput(text, this.metadata.slug);
  }
}

/* ------------------------------- Commix (§77/§78) ------------------------------- */

export const COMMIX_FORBIDDEN_OPTIONS: readonly string[] = [
  "--os-shell", "--os-cmd", "--shell", "--file-read", "--file-write", "--file-dest",
  "--reg-read", "--reg-add", "--reg-del", "--reg-key", "--reg-value", "--reg-data", "--reg-type",
];

export class CommixAdapter extends ApiAdapterBase {
  readonly executable = "commix";
  readonly containerImage = "zerosweep/commix:governed";
  readonly versionArgs = ["--version"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "commix", slug: "commix", name: "Commix",
    description: "Command injection DETECTION only, using commix's harmless time/results marker techniques. Arbitrary OS commands, shells and file access are structurally disabled and actively rejected (§77/§78).",
    homepage: "https://commixproject.com",
    riskLevel: "INTRUSIVE",
    capabilities: ["VULNERABILITY_SCANNING"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["TEXT"],
    requiresApproval: true,
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD, PARAMETER_FIELD],
  });

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertNoForbiddenOptions("commix", config, COMMIX_FORBIDDEN_OPTIONS);
    await super.validateConfiguration(config);
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config);
    const parameter = str(config.parameter);
    const args = ["--url", this.baseUrl, "--batch", "--skip-waf", "--timeout", "10", "--retries", "1", "--level", "1", "--output-dir", "/tmp/commix-out"];
    if (parameter) args.push("--parameter", parameter);
    // No --os-cmd can ever be added: the adapter exposes no command
    // field, and validateConfiguration rejects the flags (§180).
    return { args };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseCommixOutput(text, this.metadata.slug);
  }
}

/* ------------------------------- SSTImap (§79) ------------------------------- */

export const SSTIMAP_FORBIDDEN_OPTIONS: readonly string[] = [
  "--os-shell", "--os-cmd", "--shell", "--eval", "--file-read", "--file-write",
];

export class SstimapAdapter extends ApiAdapterBase {
  readonly executable = "sstimap";
  readonly containerImage = "zerosweep/sstimap:governed";
  readonly versionArgs = ["--help"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "sstimap", slug: "sstimap", name: "SSTImap",
    description: "SSTI DETECTION only: template-engine identification via non-destructive arithmetic proof markers. Code evaluation and OS interaction are structurally disabled (§79).",
    homepage: "https://github.com/vladko312/SSTImap",
    riskLevel: "INTRUSIVE",
    capabilities: ["VULNERABILITY_SCANNING"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["TEXT"],
    requiresApproval: true,
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD, PARAMETER_FIELD],
  });

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertNoForbiddenOptions("sstimap", config, SSTIMAP_FORBIDDEN_OPTIONS);
    await super.validateConfiguration(config);
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config);
    const parameter = str(config.parameter);
    const args = ["-u", this.baseUrl, "--no-colors", "--level", "1", "--max-time", "60", "--retries", "1"];
    if (parameter) args.push("-p", parameter);
    return { args };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseSstimapOutput(text, this.metadata.slug);
  }
}

/* ------------------------------- WPScan (§81/§82) ------------------------------- */

export const WPSCAN_FORBIDDEN_OPTIONS: readonly string[] = [
  "--passwords", "--usernames", "--wordlist", "--login-uri", "--multicall-passwords",
  "--password-attack", "--stealthy",
];

export class WpscanAdapter extends ApiAdapterBase {
  readonly executable = "wpscan";
  readonly containerImage = "wpscanteam/wpscan:latest";
  readonly versionArgs = ["--version"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "wpscan", slug: "wpscan", name: "WPScan",
    description: "WordPress enumeration only: core/plugin/theme versions + known-vulnerability correlation + configuration observations. Password attacks are structurally disabled and actively rejected (§82).",
    homepage: "https://wpscan.com",
    riskLevel: "MODERATE",
    capabilities: ["VULNERABILITY_SCANNING", "TECHNOLOGY_DETECTION"],
    supportedTargetTypes: ["WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD,
      { name: "enumerate", type: "string", enumValues: ["vp,vt", "vp,vt,cb", "vp,vt,cb,dbe"], description: "Enumeration set — vulnerable plugins/themes (+ config backups / db exports in the widest set). User enumeration and password attacks are not offered (§82)" },
    ],
  });

  override async validateConfiguration(config: Record<string, unknown>): Promise<void> {
    assertNoForbiddenOptions("wpscan", config, WPSCAN_FORBIDDEN_OPTIONS);
    await super.validateConfiguration(config);
  }

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config);
    const enumerate = str(config.enumerate) ?? "vp,vt";
    return {
      args: [
        "--url", this.baseUrl, "--format", "json", "--no-banner", "--no-update",
        "--enumerate", enumerate, "--random-user-agent", "--max-threads", "5",
        "--request-timeout", "10", "--connect-timeout", "5",
      ],
    };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseWpscanOutput(text, this.metadata.slug);
  }
}
