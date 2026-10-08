/**
 * Product plans (Prompt 40 §3, §6–§9, §256–§259).
 *
 * Plans are versioned: a plan's entitlements live on PlanVersion rows and
 * existing subscriptions keep referencing the version they were created
 * against (§8). The definitions below are EXAMPLE plan data (§256): they
 * carry NO commercial pricing — monetary pricing is configuration kept
 * separate from technical entitlements (§257), no currency is hardcoded
 * into entitlement logic (§258), and tax is delegated to the billing
 * provider/business process (§259).
 */
import type { FeatureKey } from "./features";

export const PRODUCT_MODES = ["COMMUNITY", "SELF_HOSTED", "SAAS", "ENTERPRISE"] as const;
export type ProductMode = (typeof PRODUCT_MODES)[number];

export const PLAN_STATUSES = ["DRAFT", "ACTIVE", "DEPRECATED", "RETIRED"] as const;
export type PlanStatus = (typeof PLAN_STATUSES)[number];

export interface ExampleEntitlement {
  featureKey: FeatureKey;
  enabled: boolean;
  /** Numeric limit where the feature is quota-bound; null = unlimited by plan. */
  limit: number | null;
}

export interface ExamplePlan {
  code: string;
  name: string;
  description: string;
  productMode: ProductMode;
  /** Example quota dimensions (§46). EXAMPLE values, not commercial offers. */
  quotas: Record<string, number | null>;
  entitlements: ExampleEntitlement[];
  /** Always null in seed data: pricing is configured separately (§257). */
  price: null;
}

const ALL_FEATURES: FeatureKey[] = [
  "ASSET_DISCOVERY", "WEB_VAPT", "API_VAPT", "NETWORK_VAPT", "CLOUD_SECURITY",
  "CONTAINER_SECURITY", "KUBERNETES_SECURITY", "SAST", "SCA", "MOBILE_VAPT",
  "BINARY_ANALYSIS", "AI_COPILOT", "REPORTING", "CLIENT_PORTAL", "INTEGRATIONS",
  "SSO", "AUDIT_EXPORT", "ADVANCED_RBAC", "CUSTOM_REPORTS",
];

const ent = (enabled: FeatureKey[], limits: Partial<Record<FeatureKey, number | null>> = {}): ExampleEntitlement[] =>
  ALL_FEATURES.map((featureKey) => ({
    featureKey,
    enabled: enabled.includes(featureKey),
    limit: limits[featureKey] ?? null,
  }));

const CORE: FeatureKey[] = ["ASSET_DISCOVERY", "WEB_VAPT", "API_VAPT", "REPORTING"];
const STANDARD: FeatureKey[] = [
  ...CORE, "NETWORK_VAPT", "SAST", "SCA", "CONTAINER_SECURITY", "AI_COPILOT", "INTEGRATIONS", "ADVANCED_RBAC",
];

/** Example plan definitions (§256). Seeded as DRAFT→ACTIVE example data. */
export const EXAMPLE_PLANS: ExamplePlan[] = [
  {
    code: "COMMUNITY",
    name: "Community (example)",
    description: "Example community-edition plan for self-hosted evaluation. Example limits only — not a commercial offer.",
    productMode: "COMMUNITY",
    quotas: { ASSETS: 25, USERS: 3, WORKSPACES: 1, CONCURRENT_SCANS: 1, MONTHLY_SCANS: 20, AI_REQUESTS: 100, STORAGE_BYTES: 1073741824, REPORTS: 20, INTEGRATIONS: 1, CLIENT_USERS: 0 },
    entitlements: ent(CORE),
    price: null,
  },
  {
    code: "TRIAL",
    name: "Trial (example)",
    description: "Example time-boxed SaaS trial plan. Granted at signup; expiry restricts trial features and preserves data (§57).",
    productMode: "SAAS",
    quotas: { ASSETS: 50, USERS: 5, WORKSPACES: 2, CONCURRENT_SCANS: 2, MONTHLY_SCANS: 50, AI_REQUESTS: 500, STORAGE_BYTES: 5368709120, REPORTS: 50, INTEGRATIONS: 2, CLIENT_USERS: 2 },
    entitlements: ent(STANDARD),
    price: null,
  },
  {
    code: "SAAS_STARTER",
    name: "SaaS Starter (example)",
    description: "Example entry SaaS plan. Example limits only.",
    productMode: "SAAS",
    quotas: { ASSETS: 100, USERS: 10, WORKSPACES: 3, CONCURRENT_SCANS: 2, MONTHLY_SCANS: 200, AI_REQUESTS: 2000, STORAGE_BYTES: 21474836480, REPORTS: 200, INTEGRATIONS: 3, CLIENT_USERS: 5 },
    entitlements: ent(STANDARD),
    price: null,
  },
  {
    code: "SAAS_PRO",
    name: "SaaS Professional (example)",
    description: "Example professional SaaS plan with client portal and custom reports. Example limits only.",
    productMode: "SAAS",
    quotas: { ASSETS: 1000, USERS: 50, WORKSPACES: 10, CONCURRENT_SCANS: 5, MONTHLY_SCANS: 2000, AI_REQUESTS: 20000, STORAGE_BYTES: 107374182400, REPORTS: 2000, INTEGRATIONS: 10, CLIENT_USERS: 50 },
    entitlements: ent([...STANDARD, "CLOUD_SECURITY", "KUBERNETES_SECURITY", "MOBILE_VAPT", "BINARY_ANALYSIS", "CLIENT_PORTAL", "CUSTOM_REPORTS", "AUDIT_EXPORT"]),
    price: null,
  },
  {
    code: "ENTERPRISE",
    name: "Enterprise (example)",
    description: "Example enterprise plan: every feature, SSO/SCIM, contract-managed. Limits set per contract.",
    productMode: "ENTERPRISE",
    quotas: { ASSETS: null, USERS: null, WORKSPACES: null, CONCURRENT_SCANS: 20, MONTHLY_SCANS: null, AI_REQUESTS: null, STORAGE_BYTES: null, REPORTS: null, INTEGRATIONS: null, CLIENT_USERS: null },
    entitlements: ent(ALL_FEATURES),
    price: null,
  },
  {
    code: "SELF_HOSTED",
    name: "Self-Hosted (example)",
    description: "Example self-hosted plan; effective entitlements come from the installed signed license when licensing is enabled (§28).",
    productMode: "SELF_HOSTED",
    quotas: { ASSETS: null, USERS: null, WORKSPACES: null, CONCURRENT_SCANS: 10, MONTHLY_SCANS: null, AI_REQUESTS: null, STORAGE_BYTES: null, REPORTS: null, INTEGRATIONS: null, CLIENT_USERS: null },
    entitlements: ent([...STANDARD, "CLOUD_SECURITY", "KUBERNETES_SECURITY", "MOBILE_VAPT", "BINARY_ANALYSIS", "CLIENT_PORTAL", "CUSTOM_REPORTS", "AUDIT_EXPORT"]),
    price: null,
  },
];

export function getExamplePlan(code: string): ExamplePlan | null {
  return EXAMPLE_PLANS.find((p) => p.code === code) ?? null;
}

/** Reserved organization/workspace slugs (§64). */
export const RESERVED_SLUGS: ReadonlySet<string> = new Set([
  "admin", "api", "app", "auth", "billing", "blog", "cdn", "client", "demo",
  "docs", "help", "legal", "login", "logout", "mail", "platform", "portal",
  "public", "register", "root", "security", "settings", "signup", "status",
  "support", "system", "terms", "privacy", "dsrclone", "www",
]);

export function isReservedSlug(slug: string): boolean {
  return RESERVED_SLUGS.has(slug.trim().toLowerCase());
}

export function isValidSlug(slug: string): boolean {
  return /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/.test(slug) && !isReservedSlug(slug);
}
