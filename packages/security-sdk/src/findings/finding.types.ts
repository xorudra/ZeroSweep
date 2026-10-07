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
  /** OS hint from network fingerprinting (Prompt 10 §35): a HINT with a
   *  confidence — never presented as fact. */
  osHint?: string;
  osConfidence?: number;
  /** CIDR/network this host was discovered under (Prompt 10 §50). */
  network?: string;
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
  /** Port state (Prompt 10 §32): OPEN is inventory, never a vulnerability. */
  state?: "OPEN" | "CLOSED" | "FILTERED" | "OPEN_FILTERED" | "UNKNOWN";
  /** CPE exactly as the scanner reported it (Prompt 10 §34) — never
   *  fabricated; input to later vulnerability-intelligence correlation. */
  cpe?: string;
  /** Sanitized service banner (Prompt 10 §36): control characters and
   *  terminal escapes stripped, HTML neutralized, size-capped BEFORE it
   *  can reach storage or UI. */
  banner?: string;
  /** Whether the service negotiates TLS (Prompt 10 §29). */
  tls?: boolean;
  /** Version/fingerprint confidence 0..1 (Prompt 10 §33): weak banner
   *  guesses stay low and never auto-create CVE findings. */
  confidence?: number;
  /** ALL adapter slugs that reported this service (Prompt 10 §31). */
  sources?: string[];
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
  /** Whether the observed handshake carried authentication material
   *  (Prompt 9 §32) — presence only; the material itself is never stored. */
  authPresent?: boolean;
}

/** An API service (Prompt 9 §3): the inventory anchor for an API surface —
 *  endpoints, operations, parameters, schemas and authentication hang off
 *  services in the API inventory graph (§37). */
export interface NormalizedApiService {
  /** Canonical base URL of the API (origin + base path). */
  baseUrl: string;
  host: string;
  apiType: "REST" | "GRAPHQL" | "WEBSOCKET" | "UNKNOWN";
  version?: string;
  /** Dominant authentication type observed/declared: NONE | BASIC |
   *  BEARER | API_KEY | COOKIE | OAUTH2 | CUSTOM_HEADER (§19). */
  authenticationType?: string;
  /** The ApiSpecification record this service was extracted from, when
   *  the producing layer knows it (§37 graph link). */
  specificationId?: string;
  /** Adapter/importer slug that reported this service (provenance, §5). */
  source: string;
  scopeStatus?: "IN_SCOPE" | "OUT_OF_SCOPE";
}

/** An imported API specification document (Prompt 9 §6): metadata +
 *  checksum + object-storage reference only — raw documents belong in
 *  object storage, never in ordinary database fields. */
export interface NormalizedApiSpecification {
  kind: "OPENAPI" | "SWAGGER" | "POSTMAN_COLLECTION" | "INSOMNIA_EXPORT" | "GRAPHQL_SCHEMA";
  version?: string;
  source: string;
  /** sha256 of the raw document bytes. */
  checksum: string;
  artifactRef?: string;
  /** URL the document was discovered at, when discovered (§9). */
  location?: string;
  parsedStatus: "PARSED" | "FAILED" | "REJECTED";
  operationCount?: number;
}

/** A reusable request/response schema (Prompt 9 §36): structure only —
 *  property NAMES, types, formats and required markers. Example VALUES
 *  and real data never enter schema records. */
export interface NormalizedApiSchema {
  /** Stable name within its service (e.g. an OpenAPI component name or a
   *  generated `POST /users requestBody` label). */
  name: string;
  schemaType: string;
  requiredFields: string[];
  /** property name → JSON-schema type/format summary (structure only). */
  properties: Record<string, string>;
  source: string;
}

/** A GraphQL service inventory record (Prompt 9 §26/§29). Introspection
 *  availability is inventory metadata — never, by itself, a finding. */
export interface NormalizedGraphqlService {
  endpointUrl: string;
  host: string;
  schemaAvailable: boolean;
  queries: number;
  mutations: number;
  subscriptions: number;
  types: number;
  authenticationRequired?: boolean;
  source: string;
  scopeStatus?: "IN_SCOPE" | "OUT_OF_SCOPE";
}

/** A JWT inspection record (Prompt 9 §23–§25/§65): fingerprint + header +
 *  REDACTED claim metadata only. The raw token is never part of this
 *  record, never persisted and never logged. */
export interface NormalizedJwtProfile {
  /** sha256 fingerprint of the raw token (one-way; §25). */
  fingerprint: string;
  algorithm: string;
  tokenType?: string;
  keyId?: string;
  issuer?: string;
  audience?: string[];
  expiresAt?: string;
  notBefore?: string;
  issuedAt?: string;
  lifetimeSeconds?: number;
  /** Claim NAMES with safe values only — sensitive claim values are
   *  replaced by REDACTED markers during inspection (§24/§25). */
  claimsSummary: Record<string, unknown>;
  source: string;
  host?: string;
  endpoint?: string;
}

/** A packet capture produced or imported for OFFLINE analysis
 *  (Prompt 10 §43–§48). tshark analysis is preferred over live sniffing;
 *  retention is policy-bound, never indefinite by default. */
export interface NormalizedPacketCapture {
  /** Object-storage reference of the raw capture artifact. */
  artifactRef: string;
  format: "PCAP" | "PCAPNG";
  /** Producing tool: tcpdump capture or an imported analyst capture. */
  source: string;
  sizeBytes?: number;
  sha256?: string;
  /** Capture bound actually applied (seconds) — captures are always
   *  duration/size bounded (§44). */
  durationSeconds?: number;
  /** Interface the capture was taken on, when the producing worker
   *  recorded it — explicit interfaces only, never "any" (§44). */
  interfaceName?: string;
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
  /** API service inventory (Prompt 9 §3/§37). */
  apiServices?: NormalizedApiService[];
  /** GraphQL service inventory (Prompt 9 §26). */
  graphqlServices?: NormalizedGraphqlService[];
  /** JWT inspection metadata — fingerprints + redacted claims only (§65). */
  jwtProfiles?: NormalizedJwtProfile[];
  /** Imported/discovered specification metadata (Prompt 9 §6). */
  apiSpecifications?: NormalizedApiSpecification[];
  /** Packet capture artifacts (Prompt 10 §43/§47): METADATA ONLY — the
   *  raw capture bytes live in object storage behind the artifact
   *  reference; raw access is permission-gated (VIEW_RAW_PCAP) and
   *  audited. Captures may contain credentials/PII, so no byte content
   *  ever travels in this record. */
  packetCaptures?: NormalizedPacketCapture[];
  artifacts: import("../artifacts/artifact.types").ArtifactMetadata[];
  metrics: Record<string, number>;
  /** True when produced by the Mock adapter — fixture data, NOT real results. */
  mock: boolean;
}
