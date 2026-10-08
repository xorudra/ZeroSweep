import { PRODUCTION_DEFAULT_BUDGET, STAGING_DEFAULT_BUDGET } from "./budget";
import type { ScanRequestBudget, TargetEnvironment, WebVaptProfileKey } from "./types";

/**
 * V2 scan profiles (Prompt 32 §122–§125).
 *
 * Profiles are DECLARATIVE: stages (the Prompt 32 §12 pipeline), the
 * tool modules each stage may use, and the default budget. A custom
 * profile is a subset composition of these — it can never exceed the
 * platform hard limits (§123) because budgets clamp in budget.ts and
 * module gates re-check risk classes in tool-capabilities.ts.
 * Production defaults are conservative (§124): no destructive modules
 * (none exist), no persistent payloads, no state-changing fuzzing.
 */

export interface WebVaptProfileDefinition {
  key: WebVaptProfileKey;
  name: string;
  kind: "WEB" | "API";
  stages: string[];
  toolSlugs: string[];
  /** Modules in this profile that send requests (vs passive/import). */
  active: boolean;
  defaultBudget: ScanRequestBudget;
  notes: string;
}

const PIPELINE = ["PREFLIGHT", "DISCOVERY", "MAPPING", "PASSIVE_ANALYSIS", "SAFE_ACTIVE_TESTING", "NORMALIZATION", "CORRELATION", "VERIFICATION", "RISK", "REPORT"] as const;

function def(d: WebVaptProfileDefinition): WebVaptProfileDefinition { return d; }

export const WEB_VAPT_PROFILE_DEFINITIONS: Record<WebVaptProfileKey, WebVaptProfileDefinition> = {
  WEB_PASSIVE: def({
    key: "WEB_PASSIVE", name: "Web Passive", kind: "WEB",
    stages: ["PREFLIGHT", "DISCOVERY", "MAPPING", "PASSIVE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK", "REPORT"],
    toolSlugs: ["whatweb", "gau", "waybackurls", "burp", "caido", "mitmproxy"],
    active: false, defaultBudget: PRODUCTION_DEFAULT_BUDGET,
    notes: "Observation and import only — no requests beyond preflight probes.",
  }),
  WEB_SAFE: def({
    key: "WEB_SAFE", name: "Web Safe", kind: "WEB",
    stages: [...PIPELINE],
    toolSlugs: ["whatweb", "httpx", "katana", "nikto", "testssl", "sslyze", "nuclei", "ffuf"],
    active: true, defaultBudget: PRODUCTION_DEFAULT_BUDGET,
    notes: "§172 baseline: discovery, mapping, safe checks, canonical findings, report.",
  }),
  WEB_STANDARD: def({
    key: "WEB_STANDARD", name: "Web Standard", kind: "WEB",
    stages: [...PIPELINE],
    toolSlugs: ["whatweb", "httpx", "katana", "nikto", "testssl", "sslyze", "nuclei", "ffuf", "feroxbuster", "gobuster", "wfuzz", "arjun", "dalfox", "xsstrike", "wpscan", "zap"],
    active: true, defaultBudget: STAGING_DEFAULT_BUDGET,
    notes: "Adds content discovery breadth + safe-marker XSS detection. HIGH modules (sqlmap/commix/sstimap) are NOT in this profile — they require a custom profile, RUN_HIGH_RISK_WEB_TESTS and a recorded approval (§16).",
  }),
  API_SAFE: def({
    key: "API_SAFE", name: "API Safe", kind: "API",
    stages: [...PIPELINE],
    toolSlugs: ["kiterunner", "schemathesis", "inql", "graphqlmap", "nuclei", "testssl"],
    active: true, defaultBudget: PRODUCTION_DEFAULT_BUDGET,
    notes: "Schema-conformance + defensive GraphQL/JWT analysis; read-oriented operations only (§46/§47).",
  }),
  API_STANDARD: def({
    key: "API_STANDARD", name: "API Standard", kind: "API",
    stages: [...PIPELINE],
    toolSlugs: ["kiterunner", "schemathesis", "inql", "graphqlmap", "nuclei", "testssl", "arjun", "zap"],
    active: true, defaultBudget: STAGING_DEFAULT_BUDGET,
    notes: "Adds parameter discovery + proxy-assisted passive analysis.",
  }),
  TLS_ONLY: def({
    key: "TLS_ONLY", name: "TLS Only", kind: "WEB",
    stages: ["PREFLIGHT", "DISCOVERY", "PASSIVE_ANALYSIS", "NORMALIZATION", "CORRELATION", "RISK", "REPORT"],
    toolSlugs: ["testssl", "sslyze", "nuclei"],
    active: true, defaultBudget: PRODUCTION_DEFAULT_BUDGET,
    notes: "TLS configuration assessment only (§83–§85).",
  }),
  CONTENT_DISCOVERY: def({
    key: "CONTENT_DISCOVERY", name: "Content Discovery", kind: "WEB",
    stages: ["PREFLIGHT", "DISCOVERY", "MAPPING", "NORMALIZATION", "CORRELATION", "RISK", "REPORT"],
    toolSlugs: ["ffuf", "feroxbuster", "gobuster", "wfuzz", "katana"],
    active: true, defaultBudget: PRODUCTION_DEFAULT_BUDGET,
    notes: "Bounded content discovery through the shared ContentDiscoveryAdapter abstraction (§20–§22).",
  }),
  TARGETED_VERIFICATION: def({
    key: "TARGETED_VERIFICATION", name: "Targeted Verification", kind: "WEB",
    stages: ["PREFLIGHT", "SAFE_ACTIVE_TESTING", "NORMALIZATION", "CORRELATION", "VERIFICATION", "RISK", "REPORT"],
    toolSlugs: ["nuclei", "dalfox"],
    active: true, defaultBudget: { ...PRODUCTION_DEFAULT_BUDGET, maxRequests: 500, maxRequestsPerSecond: 5 },
    notes: "Targeted safe retests feeding the Prompt 31 RemediationVerificationEngine (§111).",
  }),
};

export function profileDefinition(key: WebVaptProfileKey): WebVaptProfileDefinition {
  return WEB_VAPT_PROFILE_DEFINITIONS[key];
}

/** §124/§125: environment-aware default budget selection. */
export function defaultBudgetFor(key: WebVaptProfileKey, environment: TargetEnvironment): ScanRequestBudget {
  const profile = WEB_VAPT_PROFILE_DEFINITIONS[key];
  if (environment === "PRODUCTION" || environment === "UNKNOWN") {
    // Production (and unknown, treated as production) always starts
    // from the conservative budget even for broader profiles (§124).
    return { ...PRODUCTION_DEFAULT_BUDGET, maxDurationSeconds: profile.defaultBudget.maxDurationSeconds };
  }
  return profile.defaultBudget;
}
