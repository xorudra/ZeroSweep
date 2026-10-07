import { z } from "zod";
import { ASSESSMENT_PROFILES, TARGET_TYPES } from "@dsrclone/types";

const domainRe = /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const ipv4Re = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const cidrRe = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}\/([0-9]|[12][0-9]|3[0-2])$/;

export function isDomain(v: string): boolean { return domainRe.test(v); }
export function isIpv4(v: string): boolean { return ipv4Re.test(v); }
export function isCidr(v: string): boolean { return cidrRe.test(v); }

/** Target validation: the value must match the declared target type. */
export const createTargetSchema = z
  .object({
    name: z.string().min(1).max(200),
    type: z.enum(TARGET_TYPES),
    value: z.string().min(1).max(2048),
    description: z.string().max(2000).optional(),
  })
  .superRefine((data, ctx) => {
    const bad = (message: string) =>
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["value"], message });
    switch (data.type) {
      case "DOMAIN":
        if (!isDomain(data.value)) bad("value must be a valid domain name");
        break;
      case "IP_ADDRESS":
        if (!isIpv4(data.value)) bad("value must be a valid IPv4 address");
        break;
      case "CIDR":
        if (!isCidr(data.value)) bad("value must be a valid IPv4 CIDR range");
        break;
      case "WEB_APPLICATION":
      case "API":
      case "GRAPHQL": {
        let ok = false;
        try { const u = new URL(data.value); ok = u.protocol === "http:" || u.protocol === "https:"; } catch { ok = false; }
        if (!ok) bad("value must be a valid http(s) URL");
        break;
      }
      default:
        break; // repository / image / lab targets validated by their own connectors later
    }
  });
export type CreateTargetInput = z.infer<typeof createTargetSchema>;

export const updateTargetSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  value: z.string().min(1).max(2048).optional(),
  description: z.string().max(2000).optional(),
});

/** Scope: structured allow/exclude rules only — never a shell expression. */
export const scopeRulesSchema = z.object({
  includeHosts: z.array(z.string().min(1).max(253)).default([]),
  excludeHosts: z.array(z.string().min(1).max(253)).default([]),
  includeCidrs: z.array(z.string().refine(isCidr, "must be a CIDR range")).default([]),
  allowedPorts: z.array(z.number().int().min(1).max(65535)).default([]),
  allowedPaths: z.array(z.string().startsWith("/").max(1024)).default([]),
  excludedPaths: z.array(z.string().startsWith("/").max(1024)).default([]),
});
export type ScopeRules = z.infer<typeof scopeRulesSchema>;

export const createScopeSchema = z.object({
  targetId: z.string().uuid(),
  name: z.string().min(1).max(200),
  rules: scopeRulesSchema,
});
export type CreateScopeInput = z.infer<typeof createScopeSchema>;

export const createAssessmentSchema = z.object({
  name: z.string().min(1).max(200),
  targetId: z.string().uuid(),
  scopeId: z.string().uuid().optional(),
  profile: z.enum(ASSESSMENT_PROFILES),
});
export type CreateAssessmentInput = z.infer<typeof createAssessmentSchema>;

export const createScanSchema = z.object({
  assessmentId: z.string().uuid(),
});
export type CreateScanInput = z.infer<typeof createScanSchema>;

export const paginationSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  pageSize: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().max(200).optional(),
  sortBy: z.string().max(50).optional(),
  sortDir: z.enum(["asc", "desc"]).default("desc"),
});
export type PaginationInput = z.infer<typeof paginationSchema>;

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
  name: z.string().min(1).max(200),
  organizationName: z.string().min(1).max(200),
});
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1).max(200),
});

/** Credential metadata only — secret VALUES are never accepted here, only a reference. */
export const createCredentialSchema = z.object({
  name: z.string().min(1).max(200),
  type: z.enum(["API_KEY", "CLOUD", "SCM_TOKEN", "TOOL_LICENSE", "OTHER"]),
  provider: z.string().min(1).max(100),
  secretReference: z.string().min(1).max(500),
});
export type CreateCredentialInput = z.infer<typeof createCredentialSchema>;

/**
 * Prompt 8 — proxy scanner administration (§15–§21). Every schema here is
 * STRICT: unknown fields are rejected, so a request can never smuggle a
 * secret value, a URL, a command or a login script into a scanner record.
 * endpointReference is an OPAQUE NAME (uppercase identifier charset) —
 * URLs, hostnames and IPs cannot match it, which makes SSRF-by-instance
 * impossible at the validation boundary (§17/§71).
 */
export const ENDPOINT_REFERENCE_RE = /^[A-Z][A-Z0-9_:-]{2,63}$/;
const endpointReferenceSchema = z.string().regex(ENDPOINT_REFERENCE_RE, "endpointReference must be an opaque reference name (e.g. ZAP_DAEMON_PROD) — URLs, hosts and IPs are never accepted");
const credentialReferenceSchema = z.string().min(1).max(200).regex(/^[A-Za-z0-9_.:-]+$/, "credentialReference is a reference NAME, never a secret value");

export const SCANNER_TOOL_SLUGS = ["owasp-zap", "burp-suite-professional", "caido", "mitmproxy", "greenbone-openvas", "nessus-professional"] as const;

const scannerInstanceConfigSchema = z.object({
  // Prompt 11 §7/§12: logical profile → administrator-approved scanner
  // policy/config id mappings + last reported feed state. Values are
  // opaque scanner-side identifiers held as admin metadata only.
  profiles: z.record(z.string().min(1).max(120)).optional(),
  feedStatus: z.string().max(64).optional(),
  approvedInternal: z.boolean().optional(),
}).strict();

export const createScannerInstanceSchema = z.object({
  name: z.string().min(1).max(120),
  toolSlug: z.enum(SCANNER_TOOL_SLUGS),
  endpointReference: endpointReferenceSchema,
  deploymentType: z.enum(["MANAGED_DAEMON", "ADMIN_PROVIDED", "IMPORT_ONLY"]).default("MANAGED_DAEMON"),
  credentialReference: credentialReferenceSchema.optional(),
  declaredCapabilities: z.array(z.string().min(1).max(64)).max(24).optional(),
  workspaceId: z.string().uuid().optional(),
  config: scannerInstanceConfigSchema.optional(),
}).strict();
export type CreateScannerInstanceInput = z.infer<typeof createScannerInstanceSchema>;

export const updateScannerInstanceSchema = z.object({
  name: z.string().min(1).max(120).optional(),
  enabled: z.boolean().optional(),
  credentialReference: credentialReferenceSchema.nullable().optional(),
  declaredCapabilities: z.array(z.string().min(1).max(64)).max(24).optional(),
  config: scannerInstanceConfigSchema.optional(),
}).strict();
export type UpdateScannerInstanceInput = z.infer<typeof updateScannerInstanceSchema>;

export const createSessionProfileSchema = z.object({
  name: z.string().min(1).max(120),
  type: z.enum(["ANONYMOUS", "AUTHENTICATED", "API_AUTHENTICATED"]).default("ANONYMOUS"),
  credentialReference: credentialReferenceSchema.optional(),
  cookiePolicy: z.object({ allowedCookieNames: z.array(z.string().min(1).max(120)).max(32) }).strict().optional(),
  headerPolicy: z.object({ headerNames: z.array(z.string().min(1).max(120)).max(32) }).strict().optional(),
  validation: z.object({
    authenticatedUrl: z.string().url().max(2048).optional(),
    expectedStatus: z.number().int().min(100).max(599).optional(),
    expectedMarker: z.string().min(1).max(200).optional(),
  }).strict().optional(),
}).strict();
export type CreateSessionProfileInput = z.infer<typeof createSessionProfileSchema>;

export const createAuthenticationProfileSchema = z.object({
  mode: z.enum(["FORM", "BASIC", "BEARER", "API_KEY", "COOKIE", "OAUTH", "CUSTOM_HEADER"]),
  loginUrl: z.string().url().max(2048).optional(),
  usernameField: z.string().min(1).max(120).optional(),
  passwordField: z.string().min(1).max(120).optional(),
  tokenHeaderName: z.string().min(1).max(120).optional(),
  credentialReference: credentialReferenceSchema.optional(),
  // Field/header NAMES only — .strict() + this closed key set mean a
  // config can never carry a script or a secret value (§19/§20).
  config: z.object({
    successUrl: z.string().url().max(2048).optional(),
    failureMarker: z.string().min(1).max(200).optional(),
    additionalFieldNames: z.array(z.string().min(1).max(120)).max(16).optional(),
  }).strict().optional(),
}).strict();
export type CreateAuthenticationProfileInput = z.infer<typeof createAuthenticationProfileSchema>;

export const grantScanApprovalSchema = z.object({
  assessmentId: z.string().uuid(),
  scanId: z.string().uuid().optional(),
  scannerInstanceId: z.string().uuid().optional(),
  capability: z.enum(["ACTIVE_WEB_SCANNING"]).default("ACTIVE_WEB_SCANNING"),
  expiresAt: z.string().datetime().optional(),
}).strict();
export type GrantScanApprovalInput = z.infer<typeof grantScanApprovalSchema>;

export const scannerImportSchema = z.object({
  format: z.enum(["zap-json", "burp-xml", "caido-json", "har"]),
  // Raw export text; the hard byte cap is enforced by the SDK import
  // guards (10 MiB) before any parsing happens (§61/§62).
  payload: z.string().min(2).max(12 * 1024 * 1024),
  scanId: z.string().uuid(),
}).strict();
export type ScannerImportInput = z.infer<typeof scannerImportSchema>;
