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
