/**
 * OWASP API Security Top 10 mapping (Prompt 9 §41). Curated, versioned,
 * and applied ONLY by API-engine producers for API vulnerability classes
 * with sufficient evidence — a finding is never auto-mapped just because
 * it touched an API (§41). Classes without a confident mapping return
 * undefined and stay unmapped.
 */
export const OWASP_API_TAXONOMY_VERSION = "OWASP API Security Top 10 2023";

export const OWASP_API_CATEGORIES: Record<string, string> = {
  API1: "API1:2023 Broken Object Level Authorization",
  API2: "API2:2023 Broken Authentication",
  API3: "API3:2023 Broken Object Property Level Authorization",
  API4: "API4:2023 Unrestricted Resource Consumption",
  API5: "API5:2023 Broken Function Level Authorization",
  API6: "API6:2023 Unrestricted Access to Sensitive Business Flows",
  API7: "API7:2023 Server Side Request Forgery",
  API8: "API8:2023 Security Misconfiguration",
  API9: "API9:2023 Improper Inventory Management",
  API10: "API10:2023 Unsafe Consumption of APIs",
};

const CLASS_TO_API_CATEGORY: Record<string, string> = {
  // JWT configuration/policy issues are authentication failures (§24).
  JWT_ALGORITHM_CONFIGURATION: OWASP_API_CATEGORIES.API2!,
  JWT_MISSING_EXPIRY: OWASP_API_CATEGORIES.API2!,
  JWT_EXCESSIVE_LIFETIME: OWASP_API_CATEGORIES.API2!,
  JWT_ISSUER_AUDIENCE_MISMATCH: OWASP_API_CATEGORIES.API2!,
  // Sensitive data readable in token claims = excessive data exposure.
  JWT_SENSITIVE_CLAIMS: OWASP_API_CATEGORIES.API3!,
  // Exposed API documentation / debug surface = misconfiguration, and
  // shadow/undocumented inventory is API9's subject (§51 categories).
  EXPOSED_API_DOCUMENTATION: OWASP_API_CATEGORIES.API8!,
  EXPOSED_DEBUG_ENDPOINT: OWASP_API_CATEGORIES.API8!,
  // CORS on an API is a configuration issue in the API taxonomy.
  CORS_MISCONFIGURATION: OWASP_API_CATEGORIES.API8!,
};

export function owaspApiCategoryFor(vulnClass: string): string | undefined {
  return CLASS_TO_API_CATEGORY[vulnClass];
}
