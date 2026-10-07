import type { AdapterTarget } from "../adapter/adapter.interface";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterInputField, ToolMetadata } from "../adapter/adapter.types";
import { TIMEOUT_FIELD, URLS_FIELD, type ReconPlanParts } from "../recon/recon-adapter.base";
import { defaultWordlistManager, wordlistContainerPath } from "../webdiscovery/wordlists";
import { ApiAdapterBase, type ApiFindingDraft, type ParsedApi } from "./api-adapter.base";
import { emptyParsedApi, parseGraphqlmapOutput, parseInqlOutput, parseKiterunnerOutput, parseSchemathesisJUnit } from "./parsers-api";
import { apiOperationPolicy } from "./policy";
import { inspectJwt, JwtInspectionError } from "./jwt";
import type { ApiOperation } from "./types";
import { sourceFindingFingerprint } from "../vuln/analysis";
import { taxonomyFor } from "../vuln/taxonomy";

/**
 * API security tool adapters (Prompt 9 §13/§15/§22/§27/§28). All run on
 * the standard adapter lifecycle — the worker assembles validated
 * config from declared fields only; no adapter accepts a command, and
 * every plan is an argv array executed without a shell.
 */

function meta(partial: Partial<ToolMetadata> & Pick<ToolMetadata, "id" | "slug" | "name" | "description" | "riskLevel" | "capabilities" | "supportedTargetTypes" | "supportedOutputFormats">): ToolMetadata {
  return {
    category: "API",
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

export const SCHEMA_URL_FIELD: AdapterInputField = { name: "schemaUrl", type: "string", description: "Location of the imported OpenAPI document, supplied by the worker from the guarded import store (stage input) — never client input" };
export const OPERATIONS_FIELD: AdapterInputField = { name: "operations", type: "string[]", description: "Imported operations encoded as 'METHOD path operationId?' strings for the policy filter (stage input)" };
export const ALLOW_STATE_CHANGING_FIELD: AdapterInputField = { name: "allowStateChanging", type: "boolean", description: "Explicit profile/policy approval for state-changing operations — the baseline worker never sets it (§17)" };
export const WORDLIST_PROFILE_FIELD_API: AdapterInputField = { name: "wordlistProfile", type: "string", description: "Governed wordlist profile for API routes (worker-derived from the assessment profile)" };

function decodeOperations(config: Record<string, unknown>): ApiOperation[] {
  const raw = Array.isArray(config.operations) ? config.operations : [];
  return (raw as unknown[]).filter((x): x is string => typeof x === "string").map((line) => {
    const [method = "GET", path = "/", operationId] = line.split(" ");
    return { method, path, ...(operationId ? { operationId } : {}), source: "stage-input" };
  });
}

function startUrlOf(target: AdapterTarget, config: Record<string, unknown>): string {
  const urls = Array.isArray(config.urls) && config.urls.length > 0 ? (config.urls as string[]) : [];
  if (urls.length > 0) return urls[0]!;
  return target.value.includes("://") ? target.value : `https://${target.host}/`;
}

// ------------------------------- Kiterunner (§13) -------------------------------

export class KiterunnerAdapter extends ApiAdapterBase {
  readonly executable = "kr";
  readonly containerImage = "assetnote/kiterunner";
  readonly versionArgs = ["--help"];
  protected baseUrl = "";
  readonly metadata = meta({
    id: "kiterunner", slug: "kiterunner", name: "Kiterunner",
    description: "Fast API route discovery using curated, platform-governed route wordlists. Discovers routes only — it does not test authorization or modify data (§13).",
    homepage: "https://github.com/assetnote/kiterunner",
    riskLevel: "MODERATE",
    capabilities: ["API_DISCOVERY", "ROUTE_DISCOVERY"],
    supportedTargetTypes: ["API", "WEB_APPLICATION", "DOMAIN"],
    supportedOutputFormats: ["JSONL"],
    defaultTimeoutSeconds: 600, maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 600 },
    inputSchema: [
      URLS_FIELD, TIMEOUT_FIELD, WORDLIST_PROFILE_FIELD_API,
      { name: "concurrency", type: "number", min: 1, max: 50, description: "Bounded request concurrency" },
      { name: "delayMs", type: "number", min: 0, max: 5000, description: "Bounded inter-request delay (milliseconds)" },
      { name: "maxRequests", type: "number", min: 1, max: 50000, description: "API request budget (§61)" },
    ],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    this.baseUrl = startUrlOf(target, config).replace(/\/+$/, "");
    // Governed routes only (§13/§14): the wordlist is resolved from the
    // platform registry by profile — a plan can never reference an
    // arbitrary file. Kiterunner consumes the materialized route file
    // at its governed container path.
    const profile = config.wordlistProfile === "STANDARD" || config.wordlistProfile === "COMPREHENSIVE" ? config.wordlistProfile : "SMALL";
    const { primary } = defaultWordlistManager.resolveForDiscovery({ category: "API_ROUTES", profile, technologies: [] });
    const containerPath = wordlistContainerPath(primary);
    const concurrency = typeof config.concurrency === "number" ? Math.min(50, Math.max(1, Math.floor(config.concurrency))) : 10;
    const delayMs = typeof config.delayMs === "number" ? Math.min(5000, Math.max(0, Math.floor(config.delayMs))) : 100;
    return {
      args: [
        "scan", this.baseUrl,
        "-w", containerPath,
        "-x", String(concurrency),
        "--delay", `${delayMs}ms`,
        "-o", "json",
      ],
    };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseKiterunnerOutput(text, this.metadata.slug, this.baseUrl);
  }
}

// ------------------------------- Schemathesis (§15) -------------------------------

/** The ONLY checks the platform enables (§15/§62): safe conformance
 *  checks. Schemathesis' stateful chaining is never enabled (no
 *  --phases stateful), example counts are capped, and harmful-payload
 *  fuzzing is outside this configuration entirely. */
export const SCHEMATHESIS_SAFE_CHECKS = [
  "not_a_server_error", "status_code_conformance", "content_type_conformance",
  "response_schema_conformance", "response_headers_conformance",
] as const;

export class SchemathesisAdapter extends ApiAdapterBase {
  readonly executable = "schemathesis";
  readonly containerImage = "schemathesis/schemathesis";
  readonly versionArgs = ["--version"];
  /** Operations the policy excluded from the most recent plan — visible
   *  for the API_OPERATION_BLOCKED audit trail (blocking is never
   *  silent, §17). */
  blockedOperations: { method: string; path: string; operationId?: string; classification: string }[] = [];
  readonly metadata = meta({
    id: "schemathesis", slug: "schemathesis", name: "Schemathesis",
    description: "Schema-based API testing from an imported OpenAPI document, restricted to safe conformance checks and policy-approved operations only (§15/§62).",
    homepage: "https://schemathesis.readthedocs.io",
    riskLevel: "MODERATE",
    capabilities: ["SCHEMA_BASED_API_TESTING", "API_VALIDATION"],
    supportedTargetTypes: ["API", "WEB_APPLICATION"],
    supportedOutputFormats: ["XML"],
    defaultTimeoutSeconds: 900, maxTimeoutSeconds: 1800,
    resources: { cpu: "1", memory: "1Gi", timeoutSeconds: 900 },
    inputSchema: [SCHEMA_URL_FIELD, OPERATIONS_FIELD, ALLOW_STATE_CHANGING_FIELD, TIMEOUT_FIELD,
      { name: "maxRequests", type: "number", min: 1, max: 50000, description: "API request budget (§61)" }],
  });

  /**
   * The plan is built AROUND the operation policy (§15/§17): operations
   * are partitioned first; everything not automatable is excluded by
   * operationId (--exclude-name) and, unless explicitly approved,
   * non-safe methods are excluded wholesale (--include-method).
   */
  protected planFor(_target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const schemaUrl = str(config.schemaUrl);
    if (!schemaUrl) {
      throw new AdapterConfigurationError("schemathesis requires an imported OpenAPI schema location (schemaUrl) — import or discover a specification first (§15)");
    }
    const operations = decodeOperations(config);
    const allowStateChanging = config.allowStateChanging === true;
    const { blocked } = apiOperationPolicy.partition(operations, { allowStateChanging });
    this.blockedOperations = blocked.map(({ op, verdict }) => ({
      method: op.method, path: op.path, ...(op.operationId ? { operationId: op.operationId } : {}), classification: verdict.classification,
    }));
    const args: string[] = [
      "run", schemaUrl,
      "--checks", SCHEMATHESIS_SAFE_CHECKS.join(","),
      "--workers", "1",
      "--phases", "examples,coverage",
      "--hypothesis-max-examples", "10",
      "--report", "junit",
      "--report-junit-path", "schemathesis-report.xml",
    ];
    if (!allowStateChanging) args.push("--include-method", "GET,HEAD,OPTIONS");
    const blockedIds = blocked.map((b) => b.op.operationId).filter((id): id is string => !!id);
    if (blockedIds.length > 0) {
      const pattern = `^(${blockedIds.map((id) => id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|")})$`;
      args.push("--exclude-name", pattern);
    }
    return { args, outputFiles: ["schemathesis-report.xml"] };
  }

  protected parseApiOutput(text: string): ParsedApi {
    const parsed = parseSchemathesisJUnit(text, this.metadata.slug);
    if (this.blockedOperations.length > 0) {
      parsed.metrics = { ...(parsed.metrics ?? {}), blockedOperations: this.blockedOperations.length };
      parsed.warnings.push(`${this.blockedOperations.length} operation(s) were excluded by the API operation policy before execution (§17): ${this.blockedOperations.slice(0, 5).map((b) => `${b.method} ${b.path} [${b.classification}]`).join("; ")}`);
    }
    return parsed;
  }
}

// ------------------------------- InQL (§27) -------------------------------

export class InqlAdapter extends ApiAdapterBase {
  readonly executable = "inql";
  readonly containerImage = "doyensec/inql";
  readonly versionArgs = ["-h"];
  protected graphqlUrl = "";
  readonly metadata = meta({
    id: "inql", slug: "inql", name: "InQL",
    description: "GraphQL introspection capture and schema analysis. Introspection results are inventory — their availability alone is never reported as a vulnerability (§27/§29).",
    homepage: "https://github.com/doyensec/inql",
    riskLevel: "LOW",
    capabilities: ["GRAPHQL_ANALYSIS", "GRAPHQL_SCHEMA_ANALYSIS"],
    supportedTargetTypes: ["GRAPHQL", "API", "WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const urls = Array.isArray(config.urls) ? (config.urls as string[]) : [];
    this.graphqlUrl = urls.find((u) => u.toLowerCase().includes("graphql")) ?? startUrlOf(target, config);
    return { args: ["-t", this.graphqlUrl] };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseInqlOutput(text, this.metadata.slug, this.graphqlUrl);
  }
}

// ------------------------------- GraphQLmap (§28) -------------------------------

export class GraphqlmapAdapter extends ApiAdapterBase {
  readonly executable = "graphqlmap";
  readonly containerImage = "swisskyrepo/graphqlmap";
  readonly versionArgs = ["-h"];
  protected graphqlUrl = "";
  readonly metadata = meta({
    id: "graphqlmap", slug: "graphqlmap", name: "GraphQLmap",
    description: "GraphQL endpoint discovery/fingerprint support. The platform records inventory facts only — GraphQLmap's exploitation payloads are never replayed (§28).",
    homepage: "https://github.com/swisskyrepo/GraphQLmap",
    riskLevel: "LOW",
    capabilities: ["GRAPHQL_ANALYSIS"],
    supportedTargetTypes: ["GRAPHQL", "API", "WEB_APPLICATION"],
    supportedOutputFormats: ["TEXT"],
    inputSchema: [URLS_FIELD, TIMEOUT_FIELD],
  });

  protected planFor(target: AdapterTarget, config: Record<string, unknown>): ReconPlanParts {
    const urls = Array.isArray(config.urls) ? (config.urls as string[]) : [];
    this.graphqlUrl = urls.find((u) => u.toLowerCase().includes("graphql")) ?? startUrlOf(target, config);
    return { args: ["-u", this.graphqlUrl] };
  }

  protected parseApiOutput(text: string): ParsedApi {
    return parseGraphqlmapOutput(text, this.metadata.slug, this.graphqlUrl);
  }
}

// ------------------------------- jwt_tool inspection adapter (§22) -------------------------------

/**
 * JWT inspection adapter (§22–§25): NOT a subprocess tool in the scan
 * pipeline — it wraps the platform JwtInspector so tokens an authorized
 * user explicitly provides (via the API's JWT inspection endpoint, as
 * secret material in memory only) get the same analysis contract. Its
 * hard limits are the point: inspection only — signature cracking,
 * secret brute force and payload tampering DO NOT EXIST here (§22/§79).
 * The registry carries it so Tools/policy surfaces can describe the
 * capability; it is never selected for a scan stage.
 */
export class JwtToolAdapter extends ApiAdapterBase {
  readonly executable = "jwt_tool";
  readonly containerImage = "ticarpi/jwt_tool";
  readonly versionArgs = ["-h"];
  readonly metadata = meta({
    id: "jwt-tool", slug: "jwt-tool", name: "jwt_tool (inspection)",
    description: "JWT inspection only: decode, claim inventory, algorithm/expiry/sensitive-claim policy checks. No cracking, no brute force, no tampering — the raw token is never stored (§22–§25).",
    homepage: "https://github.com/ticarpi/jwt_tool",
    riskLevel: "LOW",
    capabilities: ["JWT_INSPECTION", "JWT_CONFIGURATION_ANALYSIS"],
    supportedTargetTypes: ["API", "WEB_APPLICATION"],
    supportedOutputFormats: ["JSON"],
    inputSchema: [
      { name: "tokens", type: "string[]", description: "Explicitly provided authorized test tokens (in-memory only; never persisted)" },
      { name: "expectedIssuer", type: "string" },
      { name: "expectedAudience", type: "string" },
      TIMEOUT_FIELD,
    ],
  });

  protected planFor(): ReconPlanParts {
    // No subprocess plan exists: inspection is in-process (inspectTokens)
    // and the plan record deliberately carries NO token material (§65).
    return { args: [] };
  }

  /** Inspect tokens from a validated config held by the trusted caller
   *  (API service / worker hook). Returns profiles + findings — the
   *  tokens themselves never appear in the result. */
  inspectTokens(config: Record<string, unknown>): ParsedApi {
    const out = emptyParsedApi();
    const tokens = Array.isArray(config.tokens) ? (config.tokens as unknown[]).filter((t): t is string => typeof t === "string") : [];
    for (const token of tokens) {
      try {
        const inspection = inspectJwt(token, {
          source: this.metadata.slug,
          ...(str(config.host) ? { host: str(config.host) } : {}),
          ...(str(config.endpoint) ? { endpoint: str(config.endpoint) } : {}),
          policy: {
            ...(str(config.expectedIssuer) ? { expectedIssuer: str(config.expectedIssuer) } : {}),
            ...(str(config.expectedAudience) ? { expectedAudience: str(config.expectedAudience) } : {}),
          },
        });
        out.jwtProfiles.push(inspection.profile);
        for (const f of inspection.findings) {
          const host = inspection.profile.host ?? "jwt";
          const finding: ApiFindingDraft = {
            title: f.title,
            description: f.description,
            severity: f.severity,
            confidence: f.confidence,
            host,
            endpoint: inspection.profile.endpoint,
            sourceTool: this.metadata.slug,
            sourceFingerprint: sourceFindingFingerprint({ sourceTool: this.metadata.slug, host, endpoint: inspection.profile.endpoint, vulnClass: f.vulnClass, checkId: inspection.profile.fingerprint }),
            references: [],
            cwe: taxonomyFor(f.vulnClass).cwe,
            ...(f.owaspCategory ? { owaspCategory: f.owaspCategory } : {}),
            evidence: `JWT fingerprint ${inspection.profile.fingerprint.slice(0, 12)}… alg=${inspection.profile.algorithm}; claims inspected with values redacted (§25). The raw token was not stored.`,
            evidenceDetail: { checkId: f.vulnClass, metadata: { jwtFingerprint: inspection.profile.fingerprint, algorithm: inspection.profile.algorithm } },
            remediation: taxonomyFor(f.vulnClass).remediation,
            vulnClass: f.vulnClass,
          };
          out.findings.push(finding);
        }
        out.warnings.push(...inspection.observations);
      } catch (err) {
        if (err instanceof JwtInspectionError) out.warnings.push(`a provided token could not be inspected: ${err.message}`);
        else throw err;
      }
    }
    out.metrics = { tokensAnalyzed: out.jwtProfiles.length, findings: out.findings.length };
    return out;
  }

  protected parseApiOutput(): ParsedApi {
    return emptyParsedApi();
  }
}

export function createApiAdapters(runner?: import("../recon/runner").ToolRunner): ApiAdapterBase[] {
  return [new KiterunnerAdapter(runner), new SchemathesisAdapter(runner), new InqlAdapter(runner), new GraphqlmapAdapter(runner), new JwtToolAdapter(runner)];
}
