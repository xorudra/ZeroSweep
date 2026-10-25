/**
 * Product feature registry (Prompt 40 §10/§11).
 *
 * Stable feature keys gate product capabilities. Gating is enforced by the
 * backend (EntitlementService.requireFeature) — the UI only reflects state
 * (§12). Availability additionally requires the deployment capability: an
 * entitled feature whose worker/tool is absent resolves to
 * ENTITLED_BUT_UNAVAILABLE, never to "operational" (§119, §277).
 */

export const FEATURE_KEYS = [
  "ASSET_DISCOVERY",
  "WEB_VAPT",
  "API_VAPT",
  "NETWORK_VAPT",
  "CLOUD_SECURITY",
  "CONTAINER_SECURITY",
  "KUBERNETES_SECURITY",
  "SAST",
  "SCA",
  "MOBILE_VAPT",
  "BINARY_ANALYSIS",
  "AI_COPILOT",
  "REPORTING",
  "CLIENT_PORTAL",
  "INTEGRATIONS",
  "SSO",
  "AUDIT_EXPORT",
  "ADVANCED_RBAC",
  "CUSTOM_REPORTS",
] as const;

export type FeatureKey = (typeof FEATURE_KEYS)[number];

export type MeteringStrategy = "NONE" | "PER_EVENT" | "PER_UNIT" | "PER_SEAT";
export type EnforcementStrategy = "HARD_GATE" | "QUOTA" | "HARD_GATE_AND_QUOTA";

export interface ProductFeatureDefinition {
  key: FeatureKey;
  displayName: string;
  description: string;
  /** Other product features that must also be enabled (§119). */
  productDependency: FeatureKey | null;
  /** Deployment-side dependency, in operator terms. */
  technicalDependency: string;
  meteringStrategy: MeteringStrategy;
  enforcementStrategy: EnforcementStrategy;
}

const F = (
  key: FeatureKey,
  displayName: string,
  description: string,
  technicalDependency: string,
  meteringStrategy: MeteringStrategy,
  enforcementStrategy: EnforcementStrategy,
  productDependency: FeatureKey | null = null,
): ProductFeatureDefinition => ({
  key, displayName, description, productDependency, technicalDependency, meteringStrategy, enforcementStrategy,
});

/** ProductFeatureRegistry (§11). Code-defined: identical in every deployment. */
export const PRODUCT_FEATURE_REGISTRY: ProductFeatureDefinition[] = [
  F("ASSET_DISCOVERY", "Asset Discovery", "Governed discovery of assets inside verified scope.", "scanner worker", "PER_EVENT", "HARD_GATE_AND_QUOTA"),
  F("WEB_VAPT", "Web VAPT", "Web application vulnerability assessment with governed adapters.", "scanner worker", "PER_EVENT", "HARD_GATE_AND_QUOTA"),
  F("API_VAPT", "API VAPT", "API security assessment from governed specifications and collections.", "scanner worker", "PER_EVENT", "HARD_GATE_AND_QUOTA"),
  F("NETWORK_VAPT", "Network VAPT", "Network vulnerability assessment inside verified scope.", "network-capable scanner worker", "PER_EVENT", "HARD_GATE_AND_QUOTA"),
  F("CLOUD_SECURITY", "Cloud Security", "Read-only cloud posture assessment via customer connectors.", "cloud connector configuration", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("CONTAINER_SECURITY", "Container Security", "Image and workload container security assessment.", "scanner worker", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("KUBERNETES_SECURITY", "Kubernetes Security", "Kubernetes posture assessment via read-only connectors.", "kubernetes connector configuration", "PER_UNIT", "HARD_GATE", "CONTAINER_SECURITY"),
  F("SAST", "SAST", "Static application security testing of customer repositories.", "code scanner worker", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("SCA", "SCA", "Software composition analysis of customer repositories.", "code scanner worker", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("MOBILE_VAPT", "Mobile VAPT", "Static mobile application security assessment.", "mobile analysis worker", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("BINARY_ANALYSIS", "Binary Analysis", "Static binary analysis; artifacts are never executed.", "binary analysis worker", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("AI_COPILOT", "AI Copilot", "Grounded analyst copilot over normalized findings only; it never launches exploitation.", "AI service + configured provider", "PER_EVENT", "HARD_GATE_AND_QUOTA"),
  F("REPORTING", "Reporting", "Immutable, redacted report snapshots in PDF/HTML/JSON/CSV.", "report renderer", "PER_EVENT", "HARD_GATE_AND_QUOTA"),
  F("CLIENT_PORTAL", "Client Portal", "Scoped client access to published reports and findings.", "web application", "PER_SEAT", "HARD_GATE"),
  F("INTEGRATIONS", "Integrations", "Governed outbound integrations (tickets, CI, chat, SIEM).", "integration connectors", "PER_UNIT", "HARD_GATE_AND_QUOTA"),
  F("SSO", "SSO / SCIM", "Enterprise single sign-on and SCIM provisioning (Prompt 23).", "identity provider configuration", "NONE", "HARD_GATE"),
  F("AUDIT_EXPORT", "Audit Export", "Sealed audit/evidence package export.", "report renderer", "PER_EVENT", "HARD_GATE"),
  F("ADVANCED_RBAC", "Advanced RBAC", "Fine-grained roles, API keys with typed scopes, access reviews.", "identity service", "NONE", "HARD_GATE"),
  F("CUSTOM_REPORTS", "Custom Reports", "Custom report definitions beyond the standard templates.", "report renderer", "PER_EVENT", "HARD_GATE", "REPORTING"),
];

export function getFeatureDefinition(key: string): ProductFeatureDefinition | null {
  return PRODUCT_FEATURE_REGISTRY.find((f) => f.key === key) ?? null;
}

export function isFeatureKey(value: string): value is FeatureKey {
  return (FEATURE_KEYS as readonly string[]).includes(value);
}

/**
 * Commercial tools (Prompt 39 tool-registry licensing, §122–§126). These
 * products are NEVER bundled and no license key for them ships with
 * ZeroSweep (§124). Customers supply their own license/configuration
 * (§125); until then the tool reports LICENSE_REQUIRED / NOT_CONFIGURED
 * and is never presented as operational (§227).
 */
export const COMMERCIAL_TOOL_STATUSES = [
  "NOT_CONFIGURED",
  "LICENSE_REQUIRED",
  "CONFIGURED",
  "UNAVAILABLE",
  "ERROR",
] as const;
export type CommercialToolStatus = (typeof COMMERCIAL_TOOL_STATUSES)[number];

export const COMMERCIAL_TOOLS: Array<{ slug: string; name: string; termsNote: string }> = [
  { slug: "burp-suite-professional", name: "Burp Suite Professional", termsNote: "PortSwigger license required; customer-supplied." },
  { slug: "nessus-professional", name: "Nessus Professional", termsNote: "Tenable license required; customer-supplied." },
  { slug: "plextrac", name: "PlexTrac", termsNote: "PlexTrac subscription required; connector only." },
  { slug: "binary-ninja", name: "Binary Ninja", termsNote: "Vector 35 license required; customer-supplied." },
  { slug: "ida", name: "IDA", termsNote: "Hex-Rays license required; customer-supplied." },
];

/**
 * Resolve a commercial tool's truthful status from deployment facts.
 * A commercial tool with no customer configuration is LICENSE_REQUIRED
 * (never CONFIGURED, never "working") — §123/§227.
 */
export function resolveCommercialToolStatus(facts: {
  customerConfigured: boolean;
  connectorReachable: boolean | null;
  lastError?: string | null;
}): CommercialToolStatus {
  if (facts.lastError) return "ERROR";
  if (!facts.customerConfigured) return "LICENSE_REQUIRED";
  if (facts.connectorReachable === false) return "UNAVAILABLE";
  if (facts.connectorReachable === null) return "NOT_CONFIGURED";
  return "CONFIGURED";
}
