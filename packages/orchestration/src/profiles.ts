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
  "CRAWLING", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY", "SAFE_VULNERABILITY_SCAN",
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
  ENDPOINT_DISCOVERY: S("ENDPOINT_DISCOVERY", "Endpoint Discovery", "Consolidate endpoints from crawling and technology detection.", ["URL_DISCOVERY"], ["TECHNOLOGY_DETECTION", "CRAWLING"], 5, 600, "CONTINUE_WITH_PARTIAL_DATA", true),
  PARAMETER_DISCOVERY: S("PARAMETER_DISCOVERY", "Parameter Discovery", "Discover parameters on in-scope endpoints.", ["PARAMETER_DISCOVERY"], ["ENDPOINT_DISCOVERY"], 5, 900, "CONTINUE_WITH_PARTIAL_DATA", true),
  SAFE_VULNERABILITY_SCAN: S("SAFE_VULNERABILITY_SCAN", "Safe Vulnerability Scan", "Non-destructive vulnerability checks against in-scope endpoints.", ["VULNERABILITY_SCANNING"], ["ENDPOINT_DISCOVERY"], 15, 1800, "CONTINUE_WITH_PARTIAL_DATA", true),
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
  WEB_BASELINE: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "CRAWLING", "ENDPOINT_DISCOVERY", "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  WEB_COMPREHENSIVE: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "PORT_DISCOVERY", "CRAWLING", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY", "SAFE_VULNERABILITY_SCAN", ...TAIL]),
  API_ASSESSMENT: template([...HEAD, "PASSIVE_RECON", "ASSET_DISCOVERY", "DNS_RESOLUTION", "HTTP_DISCOVERY", "TECHNOLOGY_DETECTION", "CRAWLING", "ENDPOINT_DISCOVERY", "PARAMETER_DISCOVERY", "SAFE_VULNERABILITY_SCAN", ...TAIL]),
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
