import type { Severity } from "@dsrclone/types";

/** Normalized scanner output — every adapter translates into this shape. */
export interface NormalizedFinding {
  title: string;
  description: string;
  severity: Severity;
  confidence: number; // 0..1
  host?: string;
  port?: number;
  protocol?: string;
  endpoint?: string;
  parameter?: string;
  cve?: string; // never invented: unknown stays undefined
  cwe?: string;
  cvssScore?: number;
  cvssVector?: string;
  owaspCategory?: string;
  evidence?: string;
  remediation?: string;
  references: string[];
  sourceTool: string;
  sourceFingerprint: string;
}

export interface DnsRecordSet { type: string; values: string[]; }

export interface NormalizedAsset {
  host: string;
  ip?: string;
  type: string;
  /** Provenance (Prompt 5 §18): adapter slugs that reported this asset. */
  sources?: string[];
  /** DNS records observed for this host (dnsx), grouped by record type. */
  dnsRecords?: DnsRecordSet[];
  /** Scope verdict assigned during result processing (Prompt 5 §23). */
  scopeStatus?: "IN_SCOPE" | "OUT_OF_SCOPE";
  /** True when the host resolves only to a detected wildcard DNS answer. */
  wildcardSuspect?: boolean;
}
export interface NormalizedService {
  host: string;
  port: number;
  protocol: string;
  name?: string;
  product?: string;
  version?: string;
  scheme?: string;
  statusCode?: number;
  title?: string;
  server?: string;
  /** Final redirect target when the probe followed a redirect (Prompt 5 §30).
   *  An out-of-scope target is recorded as a reference, never probed. */
  redirectLocation?: string;
}
export interface NormalizedEndpoint {
  url: string;
  method?: string;
  statusCode?: number;
  /** Parameter NAMES only (Prompt 5 §21) — values never enter inventory. */
  parameterNames?: string[];
  /** Adapter slug that discovered this endpoint. */
  source?: string;
  scopeStatus?: "IN_SCOPE" | "OUT_OF_SCOPE";
}
export interface NormalizedTechnology {
  name: string;
  version?: string;
  host?: string;
  category?: string;
  source?: string;
  confidence?: number;
}

export interface NormalizedSecurityResult {
  assets: NormalizedAsset[];
  services: NormalizedService[];
  endpoints: NormalizedEndpoint[];
  technologies: NormalizedTechnology[];
  findings: NormalizedFinding[];
  artifacts: import("../artifacts/artifact.types").ArtifactMetadata[];
  metrics: Record<string, number>;
  /** True when produced by the Mock adapter — fixture data, NOT real results. */
  mock: boolean;
}
