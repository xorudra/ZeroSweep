import type { AssessmentProfile } from "@dsrclone/types";
import type { Capability } from "@dsrclone/security-sdk";
import type { FailureStrategy } from "./state-machines";

/**
 * Stage definitions + assessment profile templates (Prompt 4 §7–§8).
 * Stage types mirror the Prisma ScanStageType enum exactly so a plan can be
 * persisted 1:1 into ScanStage rows. REPORT_PREPARATION in the spec maps to
 * the existing REPORT_GENERATION stage type.
 */

export const STAGE_TYPES = [
  "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "PASSIVE_RECON", "ASSET_DISCOVERY",
  "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "PORT_DISCOVERY",
  "CRAWLING", "CONTENT_DISCOVERY", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY",
  "WEB_SURFACE_NORMALIZATION", "SAFE_VULNERABILITY_SCAN",
  "PASSIVE_SECURITY_ANALYSIS", "ACTIVE_SECURITY_ANALYSIS",
  "API_DISCOVERY", "SPEC_IMPORT", "ROUTE_DISCOVERY", "AUTH_MAPPING",
  "SAFE_SCHEMA_TESTING", "JWT_ANALYSIS", "GRAPHQL_ANALYSIS", "WEBSOCKET_INVENTORY",
  "API_FINDING_NORMALIZATION",
  "NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION",
] as const;
export type StageType = (typeof STAGE_TYPES)[number];

export interface StageDefinition {
  type: StageType;
  name: string;
  description: string;
  /** Capabilities an adapter must provide to be selected for this stage. */
  requiredCapabilities: Capability[];
  /** Stage types (within the same plan) that must finish before this one. */
  dependencies: StageType[];
  /** Weighted-progress share within its profile (Prompt 4 §39). */
  weight: number;
  timeoutSeconds: number;
  failureStrategy: FailureStrategy;
  /** Network-capable stages pass the authorization + scope gates AGAIN in the
   *  worker immediately before execution (Prompt 4 §11–§12). */
  networkCapable: boolean;
  /** Optional cap on how many adapters may be selected for this stage
   *  (Prompt 6 §48: WEB_BASELINE content discovery uses a SMALL wordlist
   *  and a single adapter). Applied at selection time. */
  adapterLimit?: number;
  /** Any-of capability groups (Prompt 7 §14): an adapter is a candidate
   *  when it fully covers ANY one group. Used by SAFE_VULNERABILITY_SCAN,
   *  which unions vulnerability scanners (VULNERABILITY_SCANNING) with
   *  TLS assessors (TLS_ANALYSIS) in one stage. */
  capabilityGroups?: Capability[][];
  /** Per-profile adapter allowlist (Prompt 7 §50): when set, only these
   *  slugs may be selected for the stage (WEB_BASELINE runs Nuclei + TLS
   *  but not Nikto; WEB_COMPREHENSIVE runs all four). */
  adapterAllowlist?: string[];
  /** Whether an empty adapter selection may fall back to the labelled
   *  simulation adapter (default true). Prompt 8 §37/§66: the passive
   *  proxy-analysis stage must NEVER be simulated — when no scanner
   *  connector is configured the stage completes honestly with an empty
   *  selection and a passive_analysis.skipped event, instead of faking
   *  proxy findings. */
  simulationFallback?: boolean;
}

const S = (
  type: StageType, name: string, description: string, requiredCapabilities: Capability[],
  dependencies: StageType[], weight: number, timeoutSeconds: number,
  failureStrategy: FailureStrategy, networkCapable = false,
): StageDefinition => ({ type, name, description, requiredCapabilities, dependencies, weight, timeoutSeconds, failureStrategy, networkCapable });

export const STAGE_LIBRARY: Record<StageType, StageDefinition> = {
  AUTHORIZATION_CHECK: S("AUTHORIZATION_CHECK", "Authorization Check", "Re-verify target ownership, assessment approval and tenant ownership before any work.", [], [], 5, 60, "FAIL_SCAN"),
  SCOPE_VALIDATION: S("SCOPE_VALIDATION", "Scope Validation", "Validate the persisted scope rules against the target; discovered assets never expand scope.", [], ["AUTHORIZATION_CHECK"], 5, 60, "FAIL_SCAN"),
  PASSIVE_RECON: S("PASSIVE_RECON", "Passive Reconnaissance", "Passive intelligence gathering that does not actively interact with the target.", ["SUBDOMAIN_DISCOVERY"], ["SCOPE_VALIDATION"], 10, 900, "FAIL_STAGE_CONTINUE", true),
  ASSET_DISCOVERY: S("ASSET_DISCOVERY", "Asset Discovery", "Consolidate discovered assets, canonicalize and scope-check each one.", ["SUBDOMAIN_DISCOVERY"], ["PASSIVE_RECON"], 10, 600, "FAIL_STAGE_CONTINUE", true),
  DNS_RESOLUTION: S("DNS_RESOLUTION", "DNS Resolution", "Resolve in-scope hosts; re-validate resolved addresses against the SSRF blocker.", ["DNS_RESOLUTION"], ["ASSET_DISCOVERY"], 5, 300, "FAIL_STAGE_CONTINUE", true),
  HTTP_DISCOVERY: S("HTTP_DISCOVERY", "HTTP Discovery", "Probe in-scope hosts for live HTTP services.", ["HTTP_PROBING"], ["DNS_RESOLUTION"], 10, 600, "FAIL_STAGE_CONTINUE", true),
  TECHNOLOGY_DETECTION: S("TECHNOLOGY_DETECTION", "Technology Detection", "Fingerprint technologies on live HTTP services.", ["TECHNOLOGY_DETECTION"], ["HTTP_DISCOVERY"], 5, 600, "CONTINUE_WITH_PARTIAL_DATA", true),
  PORT_DISCOVERY: S("PORT_DISCOVERY", "Port Discovery", "Discover open ports on in-scope hosts (authorized profiles only).", ["PORT_DISCOVERY"], ["ASSET_DISCOVERY"], 10, 1200, "FAIL_STAGE_CONTINUE", true),
  CRAWLING: S("CRAWLING", "Web Crawling", "Crawl in-scope web surface for endpoints and parameters.", ["WEB_CRAWLING"], ["HTTP_DISCOVERY"], 10, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
  CONTENT_DISCOVERY: S("CONTENT_DISCOVERY", "Content Discovery", "Discover unlinked directories, files and routes with governed wordlists (Prompt 6): registered lists only, conservative rates, soft-404 calibration, budgets enforced.", ["CONTENT_DISCOVERY"], ["CRAWLING"], 10, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
  ENDPOINT_DISCOVERY: S("ENDPOINT_DISCOVERY", "Endpoint Discovery", "Consolidate endpoints from crawling and technology detection.", ["URL_DISCOVERY"], ["TECHNOLOGY_DETECTION", "CRAWLING"], 5, 600, "CONTINUE_WITH_PARTIAL_DATA", true),
  PARAMETER_DISCOVERY: S("PARAMETER_DISCOVERY", "Parameter Discovery", "Discover parameters on in-scope endpoints.", ["PARAMETER_DISCOVERY"], ["ENDPOINT_DISCOVERY"], 5, 900, "CONTINUE_WITH_PARTIAL_DATA", true),
  WEB_SURFACE_NORMALIZATION: S("WEB_SURFACE_NORMALIZATION", "Web Surface Normalization", "Merge crawl + content + parameter discovery into ONE canonical endpoint inventory with provenance and scope verdicts (Prompt 6 §39). Platform stage — no tool executes.", [], ["PARAMETER_DISCOVERY"], 3, 300, "FAIL_STAGE_CONTINUE"),
  SAFE_VULNERABILITY_SCAN: {
    ...S("SAFE_VULNERABILITY_SCAN", "Safe Vulnerability Scan", "Safe vulnerability detection (Nuclei governed SAFE templates + Nikto) and TLS assessment (testssl.sh + SSLyze) over the normalized web surface (Prompt 7 §14). Intrusive templates are excluded by the template policy.", ["VULNERABILITY_SCANNING"], ["WEB_SURFACE_NORMALIZATION"], 15, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["VULNERABILITY_SCANNING"], ["TLS_ANALYSIS"]],
  },
  PASSIVE_SECURITY_ANALYSIS: {
    ...S("PASSIVE_SECURITY_ANALYSIS", "Passive Security Analysis", "Passive proxy analysis through configured scanner connectors (OWASP ZAP / Burp Suite / Caido, Prompt 8 §37): endpoint + site-map import, passive issue import and traffic analysis over an isolated per-assessment context. No traffic is generated beyond the governed safe crawl, and NO simulation fallback exists — with no connector configured the stage is honestly skipped (§66).", ["PASSIVE_ANALYSIS"], ["SAFE_VULNERABILITY_SCAN"], 8, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["PASSIVE_ANALYSIS"], ["TRAFFIC_ANALYSIS"]],
    simulationFallback: false,
  },
  ACTIVE_SECURITY_ANALYSIS: {
    ...S("ACTIVE_SECURITY_ANALYSIS", "Active Security Analysis", "Governed ACTIVE scanning through scanner connectors (Prompt 8 §38). INTRUSIVE: disabled by default, present in NO profile template, and executable only behind target verification + approved scope + approved assessment + explicit active-testing enablement + RBAC + admin policy + a live, unexpired, scope-matching ScanApproval + a non-zero active budget (§8/§12/§40–§44).", ["ACTIVE_WEB_SCANNING"], ["PASSIVE_SECURITY_ANALYSIS"], 0, 1800, "FAIL_STAGE_CONTINUE", true),
    simulationFallback: false,
  },
  // Prompt 9 §39/§43: the API security pipeline. Discovery/import/auth/
  //  JWT/WebSocket stages are PLATFORM stages (engine components over
  //  captured traffic + imported inventory); route discovery, safe schema
  //  testing and GraphQL analysis are tool stages whose adapters remain
  //  policy-bound (no state-changing execution, §16/§17/§30).
  API_DISCOVERY: S("API_DISCOVERY", "API Discovery", "Consolidate the API surface from imported specifications, proxy traffic (ZAP/Burp/Caido/mitmproxy) and discovered endpoints into API service inventory (Prompt 9 §5). Platform stage — no tool executes; discovered assets never expand scope.", ["API_DISCOVERY"], ["SCOPE_VALIDATION"], 8, 300, "FAIL_STAGE_CONTINUE"),
  SPEC_IMPORT: S("SPEC_IMPORT", "Specification Import", "Summarize specifications imported for this target through the guarded import path (OpenAPI/Swagger/Postman/Insomnia/GraphQL — size/format/reference guards, §6/§7). Platform stage: the stage reports what the import store holds; it fetches nothing.", ["SPEC_IMPORT"], ["API_DISCOVERY"], 5, 300, "FAIL_STAGE_CONTINUE"),
  ROUTE_DISCOVERY: S("ROUTE_DISCOVERY", "API Route Discovery", "Discover unlinked API routes with governed route wordlists (Kiterunner, §13/§14): registered lists only, conservative rates, budgets enforced. Discovered routes are inventory, never findings.", ["ROUTE_DISCOVERY"], ["SPEC_IMPORT"], 12, 1200, "CONTINUE_WITH_PARTIAL_DATA", true),
  AUTH_MAPPING: S("AUTH_MAPPING", "Authentication Mapping", "Map declared authentication schemes and registered API auth contexts (secret REFERENCES only) onto the API inventory (Prompt 9 §19–§21). Platform stage — no credentials are used and no session is established.", [], ["ROUTE_DISCOVERY"], 5, 300, "FAIL_STAGE_CONTINUE"),
  SAFE_SCHEMA_TESTING: {
    ...S("SAFE_SCHEMA_TESTING", "Safe Schema Testing", "Schema-based API testing (Schemathesis, §15/§62): imported OpenAPI operations filtered through the API operation policy — safe methods and safe conformance checks only; state-changing, DELETE, upload, financial and auth-abuse operations are excluded before execution and counted (API_OPERATION_BLOCKED).", ["SCHEMA_BASED_API_TESTING"], ["AUTH_MAPPING"], 15, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
    capabilityGroups: [["SCHEMA_BASED_API_TESTING"], ["API_VALIDATION"]],
  },
  JWT_ANALYSIS: S("JWT_ANALYSIS", "JWT Analysis", "Inspect JWTs from authorized test contexts and captured traffic metadata: fingerprint + redacted claims + algorithm/expiry/sensitive-claim policy checks (Prompt 9 §22–§25). Inspection only — no cracking, no tampering; raw tokens are never stored. Platform stage.", ["JWT_INSPECTION"], ["SAFE_SCHEMA_TESTING"], 5, 300, "FAIL_STAGE_CONTINUE"),
  GRAPHQL_ANALYSIS: S("GRAPHQL_ANALYSIS", "GraphQL Analysis", "GraphQL endpoint confirmation + introspection schema inventory (InQL/GraphQLmap, §26–§29). Mutations are never executed; introspection availability is inventory, not a finding.", ["GRAPHQL_ANALYSIS"], ["JWT_ANALYSIS"], 8, 900, "CONTINUE_WITH_PARTIAL_DATA", true),
  WEBSOCKET_INVENTORY: S("WEBSOCKET_INVENTORY", "WebSocket Inventory", "Consolidate observed WebSocket endpoints (proxy traffic) with authentication-presence metadata (Prompt 9 §31/§32). Inventory only — no message injection or fuzzing exists. Platform stage.", ["WEBSOCKET_DISCOVERY"], ["GRAPHQL_ANALYSIS"], 3, 300, "FAIL_STAGE_CONTINUE"),
  API_FINDING_NORMALIZATION: S("API_FINDING_NORMALIZATION", "API Finding Normalization", "Fold safe-schema-testing findings, JWT inspection results and API-safe scanner checks into the normalized finding model with provenance (Prompt 9 §43). Platform stage — the shared NORMALIZATION/CORRELATION/RISK tail then applies unchanged.", [], ["PASSIVE_SECURITY_ANALYSIS"], 3, 300, "FAIL_STAGE_CONTINUE"),
  NORMALIZATION: S("NORMALIZATION", "Normalization", "Translate every tool result into the normalized security result model.", [], ["SAFE_VULNERABILITY_SCAN"], 5, 300, "FAIL_SCAN"),
  CORRELATION: S("CORRELATION", "Correlation", "Deterministically group duplicate findings by fingerprint/asset/endpoint/CVE/CWE.", [], ["NORMALIZATION"], 5, 300, "FAIL_STAGE_CONTINUE"),
  RISK_ANALYSIS: S("RISK_ANALYSIS", "Risk Analysis", "Deterministic risk scoring from normalized findings (no fabricated intel).", [], ["CORRELATION"], 3, 300, "FAIL_STAGE_CONTINUE"),
  REPORT_GENERATION: S("REPORT_GENERATION", "Report Preparation", "Mark the scan ready for reporting (REPORT_PENDING). The PDF engine is a later phase.", ["REPORT_EXPORT"], ["RISK_ANALYSIS"], 2, 300, "FAIL_STAGE_CONTINUE"),
};

/** Stages that run for every profile, in plan order. */
const TAIL: StageType[] = ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS", "REPORT_GENERATION"];
const HEAD: StageType[] = ["AUTHORIZATION_CHECK", "SCOPE_VALIDATION"];

function template(types: StageType[]): StageDefinition[] {
  return types.map((t) => STAGE_LIBRARY[t]);
}

/**
 * Profile → stage template. Since Prompt 5, PASSIVE_RECON and WEB_BASELINE
 * execute REAL recon adapters (subdomain discovery → DNS → HTTP probing →
 * technology detection → historical URL discovery → conservative crawl)
 * whenever the tool binaries are present, and degrade to the labelled
 * simulation adapter when they are not. PASSIVE_RECON stays passive: its
 * endpoint stage is fed by archive/history sources (gau/waybackurls), not by
 * active probing or crawling (Prompt 5 §40). The remaining profiles are
 * validated templates whose specialist stages land in later phases.
 * NORMALIZATION depends on the last discovery stage of each profile — handled
 * by rewriting its dependency when a profile omits SAFE_VULNERABILITY_SCAN.
 */
export const PROFILE_TEMPLATES: Record<AssessmentProfile, StageDefinition[]> = {
  PASSIVE_RECON: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "ENDPOINT_DISCOVERY", ...TAIL]),
  WEB_BASELINE: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "CRAWLING", "CONTENT_DISCOVERY", "ENDPOINT_DISCOVERY", "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", ...TAIL]),
  WEB_COMPREHENSIVE: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "PORT_DISCOVERY", "CRAWLING", "CONTENT_DISCOVERY", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY", "WEB_SURFACE_NORMALIZATION", "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", ...TAIL]),
  // Prompt 9 §39 API_BASELINE: the dedicated API pipeline (validation →
  //  discovery → spec import → routes → auth mapping → safe schema
  //  testing → JWT → GraphQL → WebSocket inventory → API-safe scan →
  //  passive analysis → API normalization → shared tail). API_COMPREHENSIVE
  //  (§40) stays architecture-only in this phase: its state-changing
  //  capabilities require per-assessment admin approval machinery.
  API_ASSESSMENT: template([...HEAD, "API_DISCOVERY", "SPEC_IMPORT", "ROUTE_DISCOVERY", "AUTH_MAPPING", "SAFE_SCHEMA_TESTING", "JWT_ANALYSIS", "GRAPHQL_ANALYSIS", "WEBSOCKET_INVENTORY", "SAFE_VULNERABILITY_SCAN", "PASSIVE_SECURITY_ANALYSIS", "API_FINDING_NORMALIZATION", ...TAIL]),
  NETWORK_ASSESSMENT: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "PORT_DISCOVERY", ...TAIL]),
  SOURCE_CODE: template([...HEAD, "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  CONTAINER: template([...HEAD, "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  CLOUD: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", ...TAIL]),
  MOBILE: template([...HEAD, "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  CUSTOM: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", ...TAIL]),
};

/**
 * Resolve a profile template into plan-ready stage definitions: dependencies
 * pointing at stages the profile does not include are rewired to the nearest
 * included ancestor chain (e.g. NORMALIZATION after PASSIVE_RECON profiles
 * depends on the last included stage), and unknown dependencies are dropped
 * here — DAG validation still rejects anything inconsistent afterwards.
 */
export function resolveTemplate(profile: AssessmentProfile): StageDefinition[] {
  const defs = PROFILE_TEMPLATES[profile].map((d) => ({ ...d, dependencies: [...d.dependencies] }));
  const present = new Set(defs.map((d) => d.type));
  const includedBefore = (type: StageType): StageType[] => {
    const idx = defs.findIndex((d) => d.type === type);
    return defs.slice(0, idx).map((d) => d.type);
  };
  for (const def of defs) {
    const substituted: StageType[] = [];
    def.dependencies = def.dependencies.filter((dep) => {
      if (present.has(dep)) return true;
      // Dependency not in this profile: substitute the nearest preceding
      // included stage so ordering survives (e.g. ENDPOINT_DISCOVERY in
      // PASSIVE_RECON follows DNS_RESOLUTION when the crawl/tech stages it
      // usually follows are not part of the profile).
      const before = includedBefore(def.type);
      const prev = before[before.length - 1];
      if (prev && !substituted.includes(prev)) substituted.push(prev);
      return false;
    });
    for (const s of substituted) if (!def.dependencies.includes(s)) def.dependencies.push(s);
    // Prompt 6 §48: WEB_BASELINE content discovery is deliberately small —
    // ONE adapter (the first by capability match), SMALL wordlists. The cap
    // is part of the template, so the plan itself records the bound.
    if (profile === "WEB_BASELINE" && def.type === "CONTENT_DISCOVERY") def.adapterLimit = 1;
    // Prompt 7 §50: WEB_BASELINE vulnerability detection is conservative —
    // Nuclei SAFE templates + TLS assessment only. Nikto joins in
    // WEB_COMPREHENSIVE (which also carries the larger approved template
    // set via the worker's profile-derived approvals).
    if (profile === "WEB_BASELINE" && def.type === "SAFE_VULNERABILITY_SCAN") {
      def.adapterAllowlist = ["nuclei", "testssl", "sslyze"];
    }
    // Prompt 9 §38: the API profile's vulnerability stage runs Nuclei's
    // API-safe check set only — Nikto (HTML-web oriented) and the TLS
    // assessors are not API tools.
    if (profile === "API_ASSESSMENT" && def.type === "SAFE_VULNERABILITY_SCAN") {
      def.adapterAllowlist = ["nuclei"];
    }
    // Tail stages keep strict ordering among themselves.
    if (def.type === "CORRELATION") def.dependencies = ["NORMALIZATION"];
    if (def.type === "RISK_ANALYSIS") def.dependencies = ["CORRELATION"];
    if (def.type === "REPORT_GENERATION") def.dependencies = ["RISK_ANALYSIS"];
    if (def.type === "NORMALIZATION") {
      const before = includedBefore("NORMALIZATION").filter((t) => t !== "AUTHORIZATION_CHECK" && t !== "SCOPE_VALIDATION");
      def.dependencies = before.length > 0 ? [before[before.length - 1]!] : ["SCOPE_VALIDATION"];
    }
  }
  return defs;
}
