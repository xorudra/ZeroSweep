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
export type EndpointType = "PAGE" | "DIRECTORY" | "FILE" | "API" | "STATIC" | "UNKNOWN";

export interface NormalizedEndpoint {
  url: string;
  method?: string;
  statusCode?: number;
  /** Parameter NAMES only (Prompt 5 §21) — values never enter inventory. */
  parameterNames?: string[];
  /** Adapter slug that discovered this endpoint. */
  source?: string;
  /** ALL adapter slugs that reported this endpoint (Prompt 6 §26):
   *  one canonical endpoint, many sources. */
  sources?: string[];
  scopeStatus?: "IN_SCOPE" | "OUT_OF_SCOPE";
  /** Response classification metadata (Prompt 6 §16): inventory signals,
   *  never vulnerability claims. */
  contentLength?: number;
  contentType?: string;
  title?: string;
  /** Redirect destination as RECORDED by the probe (Prompt 6 §20): stored
   *  as a reference, never followed across scope by discovery. */
  redirectLocation?: string;
  /** Probable route kind (Prompt 6 §41/§43): API / static / file / … */
  endpointType?: EndpointType;
  /** Inventory prioritization label, e.g. SENSITIVE_ROUTE for /admin-style
   *  routes (Prompt 6 §42) — a classification, NOT a vulnerability. */
  classification?: string;
  /** Response fingerprint from safe metadata (Prompt 6 §18) used for
   *  soft-404 / wildcard detection. */
  fingerprint?: string;
  /** True when this response matches detected wildcard-route behaviour
   *  (Prompt 6 §19). */
  wildcardSuspect?: boolean;
}

/** A discovered parameter NAME on an endpoint (Prompt 6 §27). Values are
 *  never stored — sensitive values stay redacted at the URL level (§7/§23). */
export interface NormalizedEndpointParameter {
  /** Canonical URL of the endpoint this parameter belongs to. */
  endpointUrl: string;
  name: string;
  location: "QUERY" | "PATH" | "HEADER" | "COOKIE" | "BODY";
  /** Adapter slugs that discovered this parameter (Prompt 6 §30). */
  sources?: string[];
  confidence?: number;
}

/** Form metadata revealed by crawling (Prompt 6 §33): field NAMES and
 *  encoding only. Forms are never submitted by discovery (§34). */
export interface NormalizedForm {
  endpointUrl: string;
  method: string;
  fieldNames: string[];
  encodingType?: string;
  source?: string;
}
export interface NormalizedTechnology {
  name: string;
  version?: string;
  host?: string;
  category?: string;
  source?: string;
  confidence?: number;
}

/** One observed HTTP transaction (Prompt 8 §25). Metadata + hashes live in
 *  the database; the RAW request/response bytes live in object storage and
 *  are referenced, never inlined into ordinary records (§26). The redacted
 *  display copies are produced by HttpEvidenceRedactor (§27) and are the
 *  only form normal UI surfaces may render. */
export interface NormalizedHttpTransaction {
  method: string;
  /** Canonical URL; sensitive query values are redacted during processing. */
  url: string;
  host: string;
  path: string;
  statusCode?: number;
  /** Adapter/connector slug that observed the transaction. */
  source: string;
  timestamp?: string;
  durationMs?: number;
  requestSize?: number;
  responseSize?: number;
  /** sha256 of the RAW request/response (integrity link to the artifact). */
  requestHash?: string;
  responseHash?: string;
  /** Redacted, size-capped display copies (safe for normal UI, §27/§59). */
  requestRedacted?: string;
  responseRedacted?: string;
  /** Object-storage references of the raw artifacts (§26, §60). */
  requestArtifactRef?: string;
  responseArtifactRef?: string;
}

/** A WebSocket endpoint observed by a proxy connector (Prompt 8 §49):
 *  inventory only — no WebSocket attack automation exists in this phase. */
export interface NormalizedWebSocket {
  url: string;
  origin?: string;
  subprotocol?: string;
  source: string;
}

export interface NormalizedSecurityResult {
  assets: NormalizedAsset[];
  services: NormalizedService[];
  endpoints: NormalizedEndpoint[];
  technologies: NormalizedTechnology[];
  findings: NormalizedFinding[];
  /** Endpoint parameters discovered by web-surface stages (Prompt 6 §27). */
  parameters?: NormalizedEndpointParameter[];
  /** Form metadata revealed by crawlers (Prompt 6 §33). */
  forms?: NormalizedForm[];
  /** HTTP transactions observed by proxy connectors (Prompt 8 §25). */
  transactions?: NormalizedHttpTransaction[];
  /** WebSocket endpoints observed by proxy connectors (Prompt 8 §49). */
  webSockets?: NormalizedWebSocket[];
  artifacts: import("../artifacts/artifact.types").ArtifactMetadata[];
  metrics: Record<string, number>;
  /** True when produced by the Mock adapter — fixture data, NOT real results. */
  mock: boolean;
}
