/**
 * Nuclei template governance (Prompt 7 §4–§6). Nuclei is NEVER run with
 * "all templates": every template carries a platform classification, and
 * automated scans may select only SAFE templates plus REVIEW_REQUIRED
 * templates an administrator explicitly approved. INTRUSIVE templates are
 * never automatically selected; DISABLED templates are never selected at
 * all. Unknown templates default to REVIEW_REQUIRED — the absence of a
 * curated entry is never treated as permission.
 *
 * Template ids are chosen from THIS governed catalog — never from
 * user-supplied paths or names (§4, §47/§48). Custom templates are a
 * future admin-only, reviewed, versioned workflow (§48); there is no
 * upload path here.
 */

export type TemplateClassification = "SAFE" | "REVIEW_REQUIRED" | "INTRUSIVE" | "DISABLED";

export interface NucleiTemplateMeta {
  id: string;
  name: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  tags: string[];
  classification: TemplateClassification;
  /** Vulnerability class the template's findings normalize into. */
  vulnClass: string;
  cve?: string;
  cwe?: string;
  cvssScore?: number;
  cvssVector?: string;
  references: string[];
  /** REVIEW_REQUIRED templates an admin pre-approved for the broader
   *  WEB_COMPREHENSIVE profile (§50). Baseline never includes them. */
  approvedForComprehensive?: boolean;
  /** Directory family inside the governed template collection. */
  source: string;
}

/** Frozen snapshot reference (§6): a ScanPlan records this; templates are
 *  never updated mid-assessment. */
export const NUCLEI_TEMPLATE_SNAPSHOT = {
  collection: "zerosweep-governed",
  version: "2026.10.1",
  updatedAt: "2026-10-01T00:00:00.000Z",
} as const;

/** The governed template collection path inside the tool container. Plans
 *  reference the COLLECTION, plus explicit exclusions — never user paths. */
export const GOVERNED_TEMPLATE_DIR = "/opt/zerosweep/nuclei-templates/governed";

const T = (partial: Partial<NucleiTemplateMeta> & Pick<NucleiTemplateMeta, "id" | "name" | "severity" | "classification" | "vulnClass">): NucleiTemplateMeta => ({
  tags: [], references: [], source: "governed", ...partial,
});

export const NUCLEI_TEMPLATE_CATALOG: NucleiTemplateMeta[] = [
  T({ id: "http-missing-security-headers", name: "Missing Security Headers", severity: "LOW", classification: "SAFE", vulnClass: "MISSING_SECURITY_HEADERS", tags: ["misconfig", "headers"], source: "http/misconfiguration" }),
  T({ id: "cookie-no-httponly", name: "Cookie Without HttpOnly Flag", severity: "LOW", classification: "SAFE", vulnClass: "COOKIE_NO_HTTPONLY", tags: ["misconfig", "cookie"], source: "http/misconfiguration" }),
  T({ id: "cookie-no-secure", name: "Cookie Without Secure Flag", severity: "LOW", classification: "SAFE", vulnClass: "COOKIE_NO_SECURE", tags: ["misconfig", "cookie"], source: "http/misconfiguration" }),
  T({ id: "tls-version", name: "Weak TLS Version Supported", severity: "MEDIUM", classification: "SAFE", vulnClass: "TLS_WEAK_PROTOCOL", tags: ["ssl", "tls"], source: "ssl" }),
  T({ id: "ssl-issuer-org", name: "TLS Certificate Information", severity: "INFORMATIONAL", classification: "SAFE", vulnClass: "TLS_CONFIGURATION", tags: ["ssl", "tls"], source: "ssl" }),
  T({ id: "git-config-exposure", name: "Git Config Exposure", severity: "MEDIUM", classification: "SAFE", vulnClass: "EXPOSED_FILE", tags: ["exposure", "git"], source: "http/exposures" }),
  T({ id: "exposed-env-file", name: "Exposed Environment File", severity: "HIGH", classification: "SAFE", vulnClass: "EXPOSED_FILE", tags: ["exposure", "files"], source: "http/exposures" }),
  T({ id: "tech-detect-nginx-version", name: "Technology Version Disclosure", severity: "INFORMATIONAL", classification: "SAFE", vulnClass: "INFORMATION_DISCLOSURE", tags: ["tech"], source: "http/technologies" }),
  T({ id: "http-trace-method", name: "HTTP TRACE Method Enabled", severity: "LOW", classification: "REVIEW_REQUIRED", vulnClass: "SERVER_MISCONFIGURATION", tags: ["misconfig", "methods"], source: "http/misconfiguration", approvedForComprehensive: true }),
  T({ id: "cors-misconfiguration", name: "CORS Misconfiguration", severity: "MEDIUM", classification: "REVIEW_REQUIRED", vulnClass: "CORS_MISCONFIGURATION", tags: ["misconfig", "cors"], source: "http/misconfiguration", approvedForComprehensive: true }),
  T({ id: "open-redirect", name: "Open Redirect", severity: "MEDIUM", classification: "REVIEW_REQUIRED", vulnClass: "OPEN_REDIRECT", tags: ["redirect"], source: "http/vulnerabilities", approvedForComprehensive: true }),
  T({ id: "sqli-error-based", name: "Error-Based SQL Injection Probe", severity: "HIGH", classification: "INTRUSIVE", vulnClass: "GENERIC_VULNERABILITY", tags: ["sqli", "injection"], source: "http/vulnerabilities" }),
  T({ id: "xss-reflected-probe", name: "Reflected XSS Probe", severity: "HIGH", classification: "INTRUSIVE", vulnClass: "XSS", tags: ["xss"], source: "http/vulnerabilities" }),
  T({ id: "ssrf-oast-probe", name: "SSRF Out-of-Band Probe", severity: "HIGH", classification: "INTRUSIVE", vulnClass: "GENERIC_VULNERABILITY", tags: ["ssrf", "oast"], source: "http/vulnerabilities" }),
  T({ id: "default-login-check", name: "Default Credential Check", severity: "CRITICAL", classification: "DISABLED", vulnClass: "GENERIC_VULNERABILITY", tags: ["default-login", "credential"], source: "http/default-logins" }),
  T({ id: "fuzzing-parameter-dos", name: "Parameter Fuzzing (Load)", severity: "MEDIUM", classification: "DISABLED", vulnClass: "GENERIC_VULNERABILITY", tags: ["fuzz", "dos"], source: "http/fuzzing" }),
  // Prompt 9 §38: API-safe Nuclei checks — passive exposure/observation
  // templates only. CORS + missing-authentication checks stay
  // REVIEW_REQUIRED (they interpret responses, so the comprehensive
  // approval gate keeps applying); nothing here performs injection,
  // authorization bypass or state-changing API exploitation (§38/§79).
  T({ id: "exposed-openapi-spec", name: "Exposed OpenAPI Specification", severity: "INFORMATIONAL", classification: "SAFE", vulnClass: "EXPOSED_API_DOCUMENTATION", tags: ["api", "exposure", "docs"], source: "http/exposures" }),
  T({ id: "api-debug-endpoint-exposure", name: "Exposed API Debug Endpoint", severity: "MEDIUM", classification: "SAFE", vulnClass: "EXPOSED_DEBUG_ENDPOINT", tags: ["api", "exposure", "debug"], source: "http/exposures" }),
];

const DISABLED_TAG = ["dos", "fuzz", "credential", "default-login", "bruteforce", "rce"];
const INTRUSIVE_TAG = ["intrusive", "sqli", "xss", "ssrf", "ssti", "xxe", "lfi", "rfi", "injection", "oast"];

/**
 * Classify a template (§4). A curated catalog entry wins; otherwise
 * deterministic tag/id rules apply, and anything unrecognized defaults to
 * REVIEW_REQUIRED — never SAFE.
 */
export function classifyTemplate(meta: { id: string; tags?: string[] }): { classification: TemplateClassification; curated: boolean } {
  const curated = NUCLEI_TEMPLATE_CATALOG.find((t) => t.id === meta.id);
  if (curated) return { classification: curated.classification, curated: true };
  const hay = `${meta.id} ${(meta.tags ?? []).join(" ")}`.toLowerCase();
  if (DISABLED_TAG.some((t) => hay.includes(t))) return { classification: "DISABLED", curated: false };
  if (INTRUSIVE_TAG.some((t) => hay.includes(t))) return { classification: "INTRUSIVE", curated: false };
  return { classification: "REVIEW_REQUIRED", curated: false };
}

export function templateMeta(id: string): NucleiTemplateMeta | undefined {
  return NUCLEI_TEMPLATE_CATALOG.find((t) => t.id === id);
}

export interface TemplateSelection {
  selected: NucleiTemplateMeta[];
  rejected: { id: string; classification: TemplateClassification; reason: string }[];
  snapshot: typeof NUCLEI_TEMPLATE_SNAPSHOT;
}

/**
 * The automated selection (§4): SAFE always; REVIEW_REQUIRED only when the
 * id is in the administrator-approved set; INTRUSIVE/DISABLED never — an
 * approval entry naming an intrusive template is rejected with a reason,
 * not silently honoured. `maxTemplates` (budget §8) caps the result, in
 * catalog order, deterministically.
 */
export function selectTemplates(opts: {
  approvedReviewIds?: readonly string[];
  maxTemplates?: number;
  catalog?: readonly NucleiTemplateMeta[];
} = {}): TemplateSelection {
  const catalog = opts.catalog ?? NUCLEI_TEMPLATE_CATALOG;
  const approved = new Set(opts.approvedReviewIds ?? []);
  const selected: NucleiTemplateMeta[] = [];
  const rejected: TemplateSelection["rejected"] = [];
  for (const t of catalog) {
    if (t.classification === "SAFE") selected.push(t);
    else if (t.classification === "REVIEW_REQUIRED" && approved.has(t.id)) selected.push(t);
    else rejected.push({
      id: t.id,
      classification: t.classification,
      reason: t.classification === "REVIEW_REQUIRED"
        ? "REVIEW_REQUIRED template is not administrator-approved for this scan"
        : `${t.classification} templates are never automatically selected`,
    });
  }
  const capped = opts.maxTemplates !== undefined ? selected.slice(0, Math.max(0, opts.maxTemplates)) : selected;
  for (const t of selected.slice(capped.length)) {
    rejected.push({ id: t.id, classification: t.classification, reason: `template budget maxTemplates reached` });
  }
  return { selected: capped, rejected, snapshot: NUCLEI_TEMPLATE_SNAPSHOT };
}

/** Ids a profile may treat as approved REVIEW_REQUIRED (§50):
 *  WEB_COMPREHENSIVE gets the catalog's pre-approved review set; every
 *  other profile gets none. SAFE needs no approval. */
export function approvedReviewIdsForProfile(profile: string | undefined): string[] {
  if (profile !== "WEB_COMPREHENSIVE") return [];
  return NUCLEI_TEMPLATE_CATALOG.filter((t) => t.classification === "REVIEW_REQUIRED" && t.approvedForComprehensive).map((t) => t.id);
}

/** True when a finding produced by this template id may enter automated
 *  results at all (used by the Nuclei adapter at normalize time as a
 *  defense-in-depth re-check of the plan-time selection). */
export function isTemplateAutomatable(id: string, approvedReviewIds: readonly string[] = []): boolean {
  const { classification } = classifyTemplate({ id });
  if (classification === "SAFE") return true;
  if (classification === "REVIEW_REQUIRED") return approvedReviewIds.includes(id);
  return false;
}
