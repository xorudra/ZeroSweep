import { z } from "zod";

/**
 * Prompt 29 DTO schemas. Discovery payloads are fixture/recorded
 * source output (data only). Secrets are never accepted here; a root
 * asset's verification challenge is generated server-side (§8).
 */

export const createProgramSchema = z.object({
  name: z.string().min(1).max(200),
  description: z.string().max(4000).optional(),
  monitoringEnabled: z.boolean().optional(),
  monitoringTier: z.enum(["HOURLY_LIGHT", "DAILY", "WEEKLY_DEEP"]).optional(),
});

export const patchProgramSchema = z.object({
  name: z.string().min(1).max(200).optional(),
  description: z.string().max(4000).optional(),
  status: z.enum(["DRAFT", "ACTIVE", "PAUSED", "ARCHIVED"]).optional(),
  monitoringEnabled: z.boolean().optional(),
  monitoringTier: z.enum(["HOURLY_LIGHT", "DAILY", "WEEKLY_DEEP"]).optional(),
});

export const createRootAssetSchema = z.object({
  type: z.enum(["DOMAIN", "IP", "CIDR", "CLOUD_ACCOUNT", "REPOSITORY_ORGANIZATION"]),
  value: z.string().min(1).max(500),
});

export const verifyRootAssetSchema = z.object({
  method: z.enum(["DNS_TXT", "FILE_CHALLENGE", "MANUAL_APPROVAL", "CLOUD_INTEGRATION"]),
  /** Evidence reference for the completed challenge (observation /
   *  approval record id). The service checks it; the client cannot
   *  simply assert "verified". */
  evidenceReference: z.string().min(1).max(300),
});

export const authorizeActiveTestingSchema = z.object({
  level: z.enum(["AUTHORIZED_SAFE", "AUTHORIZED_STANDARD"]),
  /** §6: authorization may carry an expiration. */
  expiresAt: z.string().datetime().optional(),
});

export const upsertPolicySchema = z.object({
  mode: z.enum(["PASSIVE_ONLY", "SAFE_ACTIVE", "CUSTOM"]).optional(),
  passiveDiscovery: z.boolean().optional(),
  dnsResolution: z.boolean().optional(),
  certificateDiscovery: z.boolean().optional(),
  httpProbing: z.boolean().optional(),
  serviceDiscovery: z.boolean().optional(),
  technologyDetection: z.boolean().optional(),
  historicalUrls: z.boolean().optional(),
  frequency: z.enum(["HOURLY", "DAILY", "WEEKLY"]).optional(),
  maxCandidatesPerRun: z.number().int().min(10).max(10000).optional(),
  allowPromotion: z.boolean().optional(),
});

export const upsertServiceProfileSchema = z.object({
  // §43: explicit approved port set; bounded, never "all ports".
  ports: z.array(z.number().int().min(1).max(65535)).min(1).max(200),
  ratePerSecond: z.number().int().min(1).max(1000).optional(),
  timeoutMs: z.number().int().min(100).max(30000).optional(),
  retries: z.number().int().min(0).max(3).optional(),
});

/** One recorded source result inside a discovery submission. This is
 *  how governed transports deliver data: recorded output + provenance,
 *  never a live fetch instruction. */
export const discoverySourceResultSchema = z.object({
  source: z.enum([
    "AMASS_PASSIVE", "SUBFINDER", "ASSETFINDER", "FINDOMAIN", "CERT_TRANSPARENCY",
    "DNS_RESOLUTION", "DNS_ZONE_OBSERVATION", "TLS_HANDSHAKE", "HTTP_PROBE", "SERVICE_DISCOVERY",
    "TECHNOLOGY_DETECTION", "HISTORICAL_URLS", "MANUAL_IMPORT",
  ]),
  version: z.string().max(60).optional(),
  status: z.enum(["OK", "ERROR"]).default("OK"),
  errorClass: z.string().max(120).optional(),
  durationMs: z.number().int().min(0).max(3_600_000).optional(),
  candidates: z.array(z.object({
    value: z.string().min(1).max(500),
    type: z.enum(["DOMAIN", "FQDN", "IP", "URL", "CLOUD_ASSET"]).optional(),
    confidence: z.number().min(0).max(1).optional(),
    rawReference: z.string().max(500).optional(),
  })).max(5000).default([]),
  dnsRecords: z.array(z.object({
    domain: z.string().min(1).max(500),
    records: z.array(z.object({
      type: z.enum(["A", "AAAA", "CNAME", "MX", "NS", "TXT"]),
      value: z.string().min(1).max(1000),
      ttl: z.number().int().min(0).optional(),
    })).max(200),
    targetResolution: z.enum(["NXDOMAIN", "NO_ADDRESS", "RESOLVES", "UNKNOWN"]).optional(),
    wildcardProbes: z.array(z.object({
      label: z.string().max(200),
      addresses: z.array(z.string().max(100)).max(20),
    })).max(20).optional(),
  })).max(1000).default([]),
  certificates: z.array(z.object({
    host: z.string().min(1).max(500),
    fingerprint: z.string().min(8).max(200),
    subject: z.string().max(500).optional(),
    issuer: z.string().max(500).optional(),
    sans: z.array(z.string().max(500)).max(200).default([]),
    notBefore: z.string().datetime().optional(),
    notAfter: z.string().datetime().optional(),
    signatureAlgorithm: z.string().max(120).optional(),
    keyType: z.string().max(60).optional(),
    keyBits: z.number().int().min(0).max(16384).optional(),
  })).max(1000).default([]),
  services: z.array(z.object({
    host: z.string().min(1).max(500),
    ip: z.string().max(100).optional(),
    port: z.number().int().min(1).max(65535),
    transport: z.enum(["tcp", "udp"]).default("tcp"),
    service: z.string().max(120).optional(),
    product: z.string().max(200).optional(),
    version: z.string().max(120).optional(),
    confidence: z.number().min(0).max(1).optional(),
  })).max(5000).default([]),
  httpObservations: z.array(z.object({
    host: z.string().min(1).max(500),
    url: z.string().min(1).max(2000),
    status: z.number().int().min(0).max(999).optional(),
    title: z.string().max(500).optional(),
    headers: z.record(z.string().max(500)).optional(),
    redirectTarget: z.string().max(2000).optional(),
    technologies: z.array(z.string().max(200)).max(50).default([]),
    certificateFingerprint: z.string().max(200).optional(),
  })).max(2000).default([]),
  technologies: z.array(z.object({
    host: z.string().min(1).max(500),
    technology: z.string().min(1).max(200),
    version: z.string().max(120).optional(),
    familyOnly: z.boolean().optional(),
    category: z.enum(["WEB_SERVER", "FRAMEWORK", "CMS", "LANGUAGE", "CDN", "WAF", "ANALYTICS", "DATABASE_HINT", "CLOUD_SERVICE", "OTHER"]).optional(),
  })).max(5000).default([]),
  historicalUrls: z.array(z.object({
    rootDomain: z.string().min(1).max(500),
    urls: z.array(z.string().max(2000)).max(2000),
  })).max(100).default([]),
});

export const runDiscoverySchema = z.object({
  trigger: z.enum(["MANUAL", "SCHEDULED"]).default("MANUAL"),
  sourceResults: z.array(discoverySourceResultSchema).max(50).default([]),
});

export const patchCandidateSchema = z.object({
  action: z.enum(["REVIEW", "CONFIRM", "REJECT", "MERGE", "DECLARE_THIRD_PARTY", "DECLARE_SHARED", "SET_CRITICALITY", "ASSIGN_OWNER"]),
  mergedIntoId: z.string().uuid().optional(),
  criticality: z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNSPECIFIED"]).optional(),
  technicalOwner: z.string().max(200).optional(),
  businessOwner: z.string().max(200).optional(),
  team: z.string().max(200).optional(),
  application: z.string().max(200).optional(),
  businessUnit: z.string().max(200).optional(),
});

export const createOwnershipRuleSchema = z.object({
  programId: z.string().uuid().optional(),
  ruleType: z.enum(["DOMAIN_SUFFIX", "CLOUD_ACCOUNT", "REPOSITORY", "TAG", "IP_RANGE"]),
  pattern: z.string().min(1).max(500),
  ownershipStatus: z.enum(["LIKELY", "THIRD_PARTY", "SHARED"]).default("LIKELY"),
  technicalOwner: z.string().max(200).optional(),
  team: z.string().max(200).optional(),
  application: z.string().max(200).optional(),
  businessUnit: z.string().max(200).optional(),
});

export const easmAskSchema = z.object({
  question: z.string().min(3).max(2000),
  assetId: z.string().uuid().optional(),
});

export const generateReportSchema = z.object({
  type: z.enum(["EXTERNAL_ATTACK_SURFACE", "NEW_ASSET", "EXPOSURE_DRIFT", "CERTIFICATE_HEALTH", "TECHNOLOGY_EXPOSURE", "UNKNOWN_ASSET", "EXECUTIVE_EASM"]),
  programId: z.string().uuid().optional(),
});
