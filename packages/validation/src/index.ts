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

export const SCANNER_TOOL_SLUGS = ["owasp-zap", "burp-suite-professional", "caido", "mitmproxy", "greenbone-openvas", "nessus-professional", "sonarqube"] as const;

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

/**
 * Prompt 12 — source repositories (§97). STRICT schemas: a repository
 * registration can never carry a secret value, an archive payload with
 * paths, or tool configuration. credentialReference is a reference NAME
 * only (same discipline as scanner instances, §9). The snapshot manifest
 * is repository DATA (file listing + manifest contents) — it is stored
 * as data, never executed (§15); entry paths are re-validated by the SDK
 * guards at the service boundary.
 */
const sourceFileEntrySchema = z.object({
  path: z.string().min(1).max(1024),
  sizeBytes: z.number().int().min(0).max(512 * 1024 * 1024),
}).strict();

export const createRepositorySchema = z.object({
  name: z.string().min(1).max(200),
  sourceKind: z.enum(["GIT_REMOTE", "UPLOADED_ARCHIVE", "LOCAL_SOURCE_SNAPSHOT", "CONNECTED_PROVIDER", "MANUAL_IMPORT"]),
  remoteUrl: z.string().url().max(2048).optional(),
  defaultBranch: z.string().min(1).max(200).optional(),
  provider: z.string().min(1).max(100).optional(),
  visibility: z.enum(["PRIVATE", "INTERNAL", "PUBLIC"]).default("PRIVATE"),
  credentialReference: credentialReferenceSchema.optional(),
  snapshotManifest: z.object({
    files: z.array(sourceFileEntrySchema).max(20000),
    manifests: z.record(z.string().max(64 * 1024)).default({}),
    commitSha: z.string().max(64).optional(),
    branch: z.string().max(200).optional(),
  }).strict().optional(),
}).strict();
export type CreateRepositoryInput = z.input<typeof createRepositorySchema>;

export const startRepositoryScanSchema = z.object({
  profile: z.enum(["SOURCE_BASELINE", "SOURCE_COMPREHENSIVE", "SECRETS_ONLY", "DEPENDENCIES_ONLY", "SAST_ONLY"]).default("SOURCE_BASELINE"),
}).strict();
export type StartRepositoryScanInput = z.input<typeof startRepositoryScanSchema>;

export const createSourceExclusionSchema = z.object({
  exclusionType: z.enum(["PATH", "RULE", "FILE_FINGERPRINT", "FINDING_FINGERPRINT", "DEPENDENCY"]),
  pattern: z.string().min(1).max(1024),
  reason: z.string().min(3).max(1000),
}).strict();
export type CreateSourceExclusionInput = z.input<typeof createSourceExclusionSchema>;

/**
 * Prompt 13 — container / Docker / Kubernetes (§91). STRICT schemas:
 * registrations carry identity + secret REFERENCES only. There is no
 * field that could hold a registry password, a kubeconfig, a cluster
 * token or a credential value — unknown keys are rejected outright, and
 * the SDK re-validates references and registry URLs (SSRF policy) at
 * the service boundary.
 */
export const registerContainerImageSchema = z.object({
  image: z.string().min(1).max(1024), // [registry/]repository[:tag][@digest]
  source: z.enum(["MANUAL", "REGISTRY", "SBOM", "CI", "RUNTIME", "CLUSTER"]).default("MANUAL"),
  registryId: z.string().uuid().optional(),
}).strict();
export type RegisterContainerImageInput = z.input<typeof registerContainerImageSchema>;

export const createContainerRegistrySchema = z.object({
  name: z.string().min(1).max(200),
  url: z.string().url().max(2048),
  provider: z.enum(["GENERIC", "DOCKER_HUB", "GHCR", "ECR", "GCR", "ACR", "HARBOR", "QUAY", "PRIVATE"]).default("GENERIC"),
  credentialReference: credentialReferenceSchema.optional(),
}).strict();
export type CreateContainerRegistryInput = z.input<typeof createContainerRegistrySchema>;

export const startContainerScanSchema = z.object({
  profile: z.enum(["CONTAINER_BASELINE", "CONTAINER_COMPREHENSIVE", "SBOM_ONLY", "IMAGE_VULNERABILITIES_ONLY", "CONTAINER_MISCONFIG_ONLY"]).default("CONTAINER_BASELINE"),
}).strict();
export type StartContainerScanInput = z.input<typeof startContainerScanSchema>;

export const createKubernetesClusterSchema = z.object({
  name: z.string().min(1).max(200),
  // A reference NAME for the API server endpoint — never a URL with
  // embedded credentials, never a kubeconfig (§32/§33).
  apiServerReference: z.string().min(1).max(300).regex(/^[A-Za-z0-9_.:/-]+$/, "apiServerReference is a reference, never a credential"),
  version: z.string().max(50).optional(),
  provider: z.enum(["GENERIC", "EKS", "AKS", "GKE", "OPENSHIFT", "ON_PREM"]).default("GENERIC"),
  credentialReference: credentialReferenceSchema.optional(),
  environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "CI", "UNKNOWN"]).default("UNKNOWN"),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
}).strict();
export type CreateKubernetesClusterInput = z.input<typeof createKubernetesClusterSchema>;

export const startKubernetesScanSchema = z.object({
  profile: z.enum(["KUBERNETES_BASELINE", "KUBERNETES_COMPREHENSIVE", "CLOUD_NATIVE_FULL"]).default("KUBERNETES_BASELINE"),
}).strict();
export type StartKubernetesScanInput = z.input<typeof startKubernetesScanSchema>;

/**
 * Falco-class runtime event ingestion (§57–§60). Events arrive from the
 * trusted sensor forwarder only; the payload is validated here and
 * sanitized again by the SDK before storage. Arbitrary user-authored
 * rules are not accepted (§61) — `rule` is the sensor's rule NAME.
 */
export const ingestRuntimeEventSchema = z.object({
  clusterName: z.string().max(300).optional(),
  node: z.string().max(300).optional(),
  namespace: z.string().max(300).optional(),
  pod: z.string().max(300).optional(),
  container: z.string().max(300).optional(),
  rule: z.string().min(1).max(300),
  priority: z.enum(["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"]),
  time: z.string().max(64), // ISO timestamp from the sensor
  outputFields: z.record(z.union([z.string().max(2000), z.number(), z.boolean(), z.null()])).default({}),
}).strict();
export type IngestRuntimeEventInput = z.input<typeof ingestRuntimeEventSchema>;

/**
 * Prompt 14 — multi-cloud security (§87). STRICT schemas: a cloud
 * account registration carries identity + a credential REFERENCE name
 * only. There is no field that could hold an AWS secret access key, an
 * Azure client secret, a GCP service-account key, a token or a password
 * — unknown keys are rejected outright, and the SDK re-validates the
 * reference shape at the service boundary (§6). Cloud references are
 * secret-manager paths, so "/" is allowed (e.g. vault:prod/aws/role);
 * whitespace and secret-shaped values are not.
 */
const cloudCredentialReferenceSchema = z.string().min(1).max(300).regex(/^[A-Za-z0-9_.:/-]+$/, "credentialReference is a reference NAME (e.g. vault:prod/aws/assessment-role), never a secret value");

const cloudRegionList = z.array(z.string().min(1).max(64)).max(500).default([]);
const cloudUnitList = z.array(z.string().min(1).max(512)).max(1000).default([]);

export const registerCloudAccountSchema = z.object({
  name: z.string().min(1).max(200),
  provider: z.enum(["AWS", "AZURE", "GCP"]),
  // AWS account id / Azure subscription id / GCP project id — the
  // provider's identifier for the estate. NOT a credential (§4).
  externalAccountId: z.string().min(1).max(512),
  credentialReference: cloudCredentialReferenceSchema.optional(),
  environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "CI", "UNKNOWN"]).default("UNKNOWN"),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
  scope: z.object({
    includeRegions: cloudRegionList,
    excludeRegions: cloudRegionList,
    includeUnits: cloudUnitList,
    excludeUnits: cloudUnitList,
    includeResources: cloudUnitList,
    excludeResources: cloudUnitList,
  }).strict().optional(),
}).strict();
export type RegisterCloudAccountInput = z.input<typeof registerCloudAccountSchema>;

export const startCloudScanSchema = z.object({
  profile: z.enum([
    "CLOUD_INVENTORY", "CLOUD_BASELINE", "CLOUD_COMPREHENSIVE", "IAM_REVIEW",
    "PUBLIC_EXPOSURE_REVIEW", "COMPLIANCE_ASSESSMENT", "IAC_TO_CLOUD_CORRELATION",
  ]).default("CLOUD_BASELINE"),
}).strict();
export type StartCloudScanInput = z.input<typeof startCloudScanSchema>;

/**
 * Prompt 15 — Active Directory domain registration (§4/§7). Directory
 * credentials are secret REFERENCES only, under the same reference
 * discipline as cloud (§6 there): a value-shaped string is refused by
 * the shape here and again at the service boundary. The domain's DNS
 * name is the target value; registration records identity metadata
 * only — never a password, never a hash.
 */
const directoryCredentialReferenceSchema = z.string().min(1).max(300).regex(/^[A-Za-z0-9_.:/-]+$/, "credentialReference is a reference NAME (e.g. vault:prod/ad/assessment-account), never a secret value");

const dnsNameSchema = z.string().min(3).max(253).regex(/^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/, "dnsName must be a DNS domain name (e.g. corp.example)");

export const registerAdDomainSchema = z.object({
  name: z.string().min(1).max(200),
  dnsName: dnsNameSchema,
  netbiosName: z.string().min(1).max(64).optional(),
  domainSid: z.string().min(1).max(128).regex(/^S-1-5-21(-[0-9]+)+$/, "domainSid must be a domain SID (S-1-5-21-…)").optional(),
  functionalLevel: z.string().min(1).max(64).optional(),
  forestName: z.string().min(1).max(200).optional(),
  forestRootDomain: dnsNameSchema.optional(),
  environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB", "UNKNOWN"]).default("UNKNOWN"),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("HIGH"),
  // §7: the assessment identity profile — least privilege by default;
  // Domain Admin is never requested (§8).
  credentialProfileName: z.string().min(1).max(200).optional(),
  identityKind: z.enum(["READ_ONLY_DOMAIN", "APPROVED_DIRECTORY_AUDITOR"]).default("READ_ONLY_DOMAIN"),
  credentialReference: directoryCredentialReferenceSchema.optional(),
  // §11: explicitly approved domain controllers for this domain.
  domainControllers: z.array(z.object({
    hostname: z.string().min(1).max(253),
    ipAddresses: z.array(z.string().min(1).max(64)).max(16).default([]),
  }).strict()).max(64).default([]),
}).strict();
export type RegisterAdDomainInput = z.input<typeof registerAdDomainSchema>;

export const startAdScanSchema = z.object({
  profile: z.enum([
    "AD_INVENTORY", "AD_BASELINE", "AD_COMPREHENSIVE", "ADCS_POSTURE",
    "SMB_POSTURE", "IDENTITY_GRAPH", "ATTACK_PATH_ANALYSIS",
  ]).default("AD_BASELINE"),
}).strict();
export type StartAdScanInput = z.input<typeof startAdScanSchema>;

// ── Prompt 17: mobile application VAPT (§100) ─────────────────────
// Registration records identity only; build upload carries artifact
// METADATA + the bounded extracted-artifact record (the binary bytes
// themselves move through object storage, never this API); dynamic
// session requests name governed ACTIONS only — a shell command, a
// script body or a device serial can never be expressed here (§59/
// §72/§75), and the strict object shape rejects unknown keys.
const mobilePlatformSchema = z.enum(["ANDROID", "IOS"]);

export const registerMobileAppSchema = z.object({
  name: z.string().min(1).max(200),
  platform: mobilePlatformSchema,
  packageName: z.string().min(1).max(255).regex(/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/, "packageName must be a dotted application id").optional(),
  bundleId: z.string().min(1).max(255).regex(/^[A-Za-z][A-Za-z0-9_-]*(\.[A-Za-z][A-Za-z0-9_-]*)+$/, "bundleId must be a dotted bundle identifier").optional(),
  owner: z.string().min(1).max(200).optional(),
  projectRef: z.string().min(1).max(200).optional(),
  environment: z.enum(["PRODUCTION", "STAGING", "DEVELOPMENT", "LAB", "UNKNOWN"]).default("UNKNOWN"),
  criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("HIGH"),
}).strict().refine((v) => (v.platform === "ANDROID" ? !!v.packageName : !!v.bundleId), {
  message: "ANDROID applications require packageName; IOS applications require bundleId",
});
export type RegisterMobileAppInput = z.input<typeof registerMobileAppSchema>;

const archiveEntrySchema = z.object({
  name: z.string().min(1).max(1024),
  uncompressedSize: z.number().int().min(0),
  compressedSize: z.number().int().min(0),
  isDirectory: z.boolean(),
  isSymlink: z.boolean(),
  unixMode: z.number().int().optional(),
}).strict();

export const uploadMobileBuildSchema = z.object({
  versionName: z.string().min(1).max(64).optional(),
  versionCode: z.number().int().min(0).optional(),
  buildNumber: z.string().min(1).max(64).optional(),
  fileName: z.string().min(1).max(255),
  declaredSha256: z.string().regex(/^[a-f0-9]{64}$/, "declaredSha256 must be a SHA-256 hex digest").optional(),
  artifactSizeBytes: z.number().int().min(0),
  artifactReference: z.string().min(1).max(512).optional(),
  // The pre-read archive central directory (zip-slip/bomb discipline
  // runs over it at intake, §6/§107).
  archiveEntries: z.array(archiveEntrySchema).max(20000).optional(),
  // Bounded extracted artifacts registered at intake (§6) — manifest /
  // plist text, decompiled snippets, library inventory. Sanitized +
  // secret-redacted by the service before persistence (§24/§28).
  analysisArtifacts: z.record(z.string(), z.unknown()).optional(),
  signingMetadata: z.record(z.string(), z.unknown()).optional(),
}).strict();
export type UploadMobileBuildInput = z.input<typeof uploadMobileBuildSchema>;

export const startMobileScanSchema = z.object({
  profile: z.enum([
    "MOBILE_STATIC_BASELINE", "MOBILE_STATIC_COMPREHENSIVE", "MOBILE_SECRETS_ONLY",
    "MOBILE_BINARY_ANALYSIS", "MOBILE_DYNAMIC_CONTROLLED", "MOBILE_FULL_CONTROLLED", "MOBILE",
  ]).default("MOBILE_STATIC_BASELINE"),
  buildId: z.string().min(1).optional(),
}).strict();
export type StartMobileScanInput = z.input<typeof startMobileScanSchema>;

export const createMobileDynamicSessionSchema = z.object({
  buildId: z.string().min(1),
  deviceId: z.string().min(1).optional(),
  profile: z.enum(["MOBILE_DYNAMIC_CONTROLLED", "MOBILE_FULL_CONTROLLED"]).default("MOBILE_DYNAMIC_CONTROLLED"),
  // Governed action NAMES only (§58/§73). Shell/script/command-shaped
  // requests are refused + audited by the service; prohibited actions
  // (§75) can never execute.
  requestedActions: z.array(z.string().min(1).max(128)).max(32).default([]),
  moduleIds: z.array(z.string().min(1)).max(16).default([]),
  instrumentationApproved: z.boolean().default(false),
  trafficCapture: z.boolean().default(false),
}).strict();
export type CreateMobileDynamicSessionInput = z.input<typeof createMobileDynamicSessionSchema>;

export const registerMobileDeviceSchema = z.object({
  name: z.string().min(1).max(200),
  platform: mobilePlatformSchema,
  deviceKind: z.enum(["EMULATOR", "PHYSICAL"]).default("EMULATOR"),
  osVersion: z.string().min(1).max(64).optional(),
  capabilities: z.array(z.string().min(1).max(64)).max(32).default([]),
  dedicatedNetwork: z.boolean().default(true),
}).strict();
export type RegisterMobileDeviceInput = z.input<typeof registerMobileDeviceSchema>;
