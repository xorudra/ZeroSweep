import type { ToolCapabilityRecord, ToolRiskClass } from "./types";

/**
 * Tool capability registry — V2 view (Prompt 32 §14–§16).
 *
 * This EXTENDS the platform ToolRegistry with the capability/risk
 * metadata the V2 orchestrator plans against; it never replaces the
 * registry and never changes a tool's enablement. Risk classes are
 * platform-assigned (§15): PASSIVE tools only observe or import, LOW
 * tools send bounded read-only probes, MODERATE tools run governed
 * detection payloads with safe markers, HIGH tools are detection-only
 * injection testers whose dangerous modes are structurally disabled in
 * their adapters (Prompt 32 §74/§78). There is no destructive class.
 *
 * §16 profile policy: HIGH-risk modules require an explicit profile,
 * active authorization AND the RUN_HIGH_RISK_WEB_TESTS permission;
 * MODERATE modules require an explicit profile + authorization.
 */

type Cap = Omit<ToolCapabilityRecord, "adapterVersion" | "parserVersion"> & Partial<Pick<ToolCapabilityRecord, "adapterVersion" | "parserVersion">>;

function cap(c: Cap): ToolCapabilityRecord {
  return { adapterVersion: "1.0.0", parserVersion: "1.0.0", ...c };
}

const R = { cpu: "1", memory: "512Mi" };
const R2 = { cpu: "2", memory: "1Gi" };

export const WEB_API_TOOL_CAPABILITIES: readonly ToolCapabilityRecord[] = [
  // ---- passive / import-only (§60–§65) ----
  cap({ slug: "whatweb", name: "WhatWeb", category: "WEB", capabilities: ["TECHNOLOGY_DETECTION"], passive: true, supportedTargetTypes: ["WEB_APPLICATION", "DOMAIN"], authenticationSupport: false, riskClass: "PASSIVE", defaultTimeoutSeconds: 300, resourceProfile: R }),
  cap({ slug: "gau", name: "gau", category: "RECON", capabilities: ["HISTORICAL_URL_DISCOVERY"], passive: true, supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION"], authenticationSupport: false, riskClass: "PASSIVE", defaultTimeoutSeconds: 300, resourceProfile: R }),
  cap({ slug: "waybackurls", name: "Waybackurls", category: "RECON", capabilities: ["HISTORICAL_URL_DISCOVERY"], passive: true, supportedTargetTypes: ["DOMAIN", "WEB_APPLICATION"], authenticationSupport: false, riskClass: "PASSIVE", defaultTimeoutSeconds: 300, resourceProfile: R }),
  cap({ slug: "burp", name: "Burp Suite (connector)", category: "PROXY", capabilities: ["TRAFFIC_IMPORT", "ISSUE_IMPORT", "PASSIVE_SECURITY_ANALYSIS"], passive: true, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: true, riskClass: "PASSIVE", defaultTimeoutSeconds: 900, resourceProfile: R2 }),
  cap({ slug: "caido", name: "Caido (connector)", category: "PROXY", capabilities: ["TRAFFIC_IMPORT", "ISSUE_IMPORT"], passive: true, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: true, riskClass: "PASSIVE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "mitmproxy", name: "mitmproxy (connector)", category: "PROXY", capabilities: ["TRAFFIC_IMPORT"], passive: true, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: true, riskClass: "PASSIVE", defaultTimeoutSeconds: 600, resourceProfile: R }),
  // ---- low: bounded read-only probing ----
  cap({ slug: "httpx", name: "httpx", category: "RECON", capabilities: ["HTTP_DISCOVERY", "TECHNOLOGY_DETECTION"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "DOMAIN", "API"], authenticationSupport: false, riskClass: "LOW", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "katana", name: "Katana", category: "WEB", capabilities: ["CRAWLING", "ENDPOINT_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: true, riskClass: "LOW", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "nikto", name: "Nikto", category: "WEB", capabilities: ["WEB_SERVER_ANALYSIS", "VULNERABILITY_SCANNING"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "LOW", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "testssl", name: "testssl.sh", category: "TLS", capabilities: ["TLS_ANALYSIS"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API", "DOMAIN"], authenticationSupport: false, riskClass: "LOW", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "sslyze", name: "SSLyze", category: "TLS", capabilities: ["TLS_ANALYSIS"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API", "DOMAIN"], authenticationSupport: false, riskClass: "LOW", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "kiterunner", name: "Kiterunner", category: "API", capabilities: ["API_DISCOVERY", "ROUTE_DISCOVERY"], passive: false, supportedTargetTypes: ["API", "WEB_APPLICATION"], authenticationSupport: false, riskClass: "LOW", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "arjun", name: "Arjun", category: "WEB", capabilities: ["PARAMETER_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: false, riskClass: "LOW", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "zap", name: "OWASP ZAP (connector)", category: "PROXY", capabilities: ["CRAWLING", "PASSIVE_SECURITY_ANALYSIS", "ACTIVE_WEB_SCANNING"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: true, riskClass: "LOW", defaultTimeoutSeconds: 1800, resourceProfile: R2 }),
  // ---- moderate: governed detection payloads, safe markers only ----
  cap({ slug: "ffuf", name: "ffuf", category: "WEB", capabilities: ["CONTENT_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "feroxbuster", name: "Feroxbuster", category: "WEB", capabilities: ["CONTENT_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "gobuster", name: "Gobuster", category: "WEB", capabilities: ["CONTENT_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "wfuzz", name: "Wfuzz", category: "WEB", capabilities: ["CONTENT_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "nuclei", name: "Nuclei", category: "WEB", capabilities: ["VULNERABILITY_SCANNING", "TECHNOLOGY_DETECTION", "TLS_ANALYSIS"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API", "DOMAIN"], authenticationSupport: true, riskClass: "MODERATE", defaultTimeoutSeconds: 1200, resourceProfile: R }),
  cap({ slug: "dalfox", name: "Dalfox", category: "WEB", capabilities: ["VULNERABILITY_SCANNING", "PARAMETER_DISCOVERY"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "xsstrike", name: "XSStrike", category: "WEB", capabilities: ["VULNERABILITY_SCANNING"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "wpscan", name: "WPScan", category: "WEB", capabilities: ["VULNERABILITY_SCANNING", "TECHNOLOGY_DETECTION"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "schemathesis", name: "Schemathesis", category: "API", capabilities: ["SCHEMA_TESTING"], passive: false, supportedTargetTypes: ["API"], authenticationSupport: true, riskClass: "MODERATE", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "graphqlmap", name: "GraphQLmap", category: "API", capabilities: ["GRAPHQL_ANALYSIS"], passive: false, supportedTargetTypes: ["API"], authenticationSupport: false, riskClass: "MODERATE", defaultTimeoutSeconds: 600, resourceProfile: R }),
  cap({ slug: "inql", name: "InQL", category: "API", capabilities: ["GRAPHQL_ANALYSIS"], passive: false, supportedTargetTypes: ["API"], authenticationSupport: true, riskClass: "MODERATE", defaultTimeoutSeconds: 600, resourceProfile: R }),
  // ---- high: detection-only injection testers (dangerous modes disabled) ----
  cap({ slug: "sqlmap", name: "SQLmap", category: "WEB", capabilities: ["VULNERABILITY_SCANNING"], passive: false, supportedTargetTypes: ["WEB_APPLICATION", "API"], authenticationSupport: true, riskClass: "HIGH", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "commix", name: "Commix", category: "WEB", capabilities: ["VULNERABILITY_SCANNING"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "HIGH", defaultTimeoutSeconds: 900, resourceProfile: R }),
  cap({ slug: "sstimap", name: "SSTImap", category: "WEB", capabilities: ["VULNERABILITY_SCANNING"], passive: false, supportedTargetTypes: ["WEB_APPLICATION"], authenticationSupport: false, riskClass: "HIGH", defaultTimeoutSeconds: 900, resourceProfile: R }),
];

const BY_SLUG = new Map(WEB_API_TOOL_CAPABILITIES.map((t) => [t.slug, t]));

export function toolCapability(slug: string): ToolCapabilityRecord | undefined {
  return BY_SLUG.get(slug);
}

export function toolsByRiskClass(riskClass: ToolRiskClass): ToolCapabilityRecord[] {
  return WEB_API_TOOL_CAPABILITIES.filter((t) => t.riskClass === riskClass);
}

export interface ModuleGateInput {
  slug: string;
  /** Was the module explicitly selected by the profile/plan? (§16) */
  explicitProfile: boolean;
  /** Active-testing authorization exists for the target (§6). */
  activeAuthorization: boolean;
  /** Caller holds RUN_HIGH_RISK_WEB_TESTS (§167). */
  highRiskPermission: boolean;
  /** A recorded approval exists for high-risk modules (§16 optional approval). */
  approvalRecorded?: boolean;
}

export interface ModuleGateResult {
  allowed: boolean;
  reason: string;
  riskClass: ToolRiskClass | null;
}

/**
 * §16 profile policy gate for a single module. Unknown tools are
 * denied (never defaulted in). PASSIVE/LOW need authorization only;
 * MODERATE adds explicit profile selection; HIGH adds the dedicated
 * permission and a recorded approval.
 */
export function evaluateModuleGate(input: ModuleGateInput): ModuleGateResult {
  const record = toolCapability(input.slug);
  if (!record) return { allowed: false, reason: `unknown tool module '${input.slug}' — not in the capability registry (§14)`, riskClass: null };
  if (record.passive) return { allowed: true, reason: "passive module — observation/import only", riskClass: record.riskClass };
  if (!input.activeAuthorization) return { allowed: false, reason: "no active-testing authorization for target (§6)", riskClass: record.riskClass };
  if (record.riskClass === "MODERATE" && !input.explicitProfile) {
    return { allowed: false, reason: "MODERATE module requires explicit profile selection (§16)", riskClass: record.riskClass };
  }
  if (record.riskClass === "HIGH") {
    if (!input.explicitProfile) return { allowed: false, reason: "HIGH module requires explicit profile selection (§16)", riskClass: record.riskClass };
    if (!input.highRiskPermission) return { allowed: false, reason: "HIGH module requires RUN_HIGH_RISK_WEB_TESTS permission (§167)", riskClass: record.riskClass };
    if (!input.approvalRecorded) return { allowed: false, reason: "HIGH module requires a recorded approval (§16)", riskClass: record.riskClass };
  }
  return { allowed: true, reason: `${record.riskClass} module permitted by profile policy`, riskClass: record.riskClass };
}
