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
  // ── Prompt 12 — source-code finding extensions (§59). All optional;
  // populated only by code-security adapters/parsers. Paths are ALWAYS
  // repository-relative (§60) and snippets are minimal + redacted (§61/§62).
  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  /** The tool rule / check identifier that produced the finding (§59). */
  ruleId?: string;
  /** Sanitized dataflow steps for taint-style findings (§63): locations
   *  and short labels only — never raw source dumps. */
  codeFlow?: { label: string; filePath: string; startLine?: number; endLine?: number }[];
  /** Secret metadata (§40): TYPE + location + one-way fingerprint +
   *  redacted preview. The raw secret value NEVER appears here — it is
   *  redacted at parse time and exists nowhere in the platform. */
  secret?: NormalizedSecretFinding;
  /** Dependency (SCA) extensions (§45/§73/§74). */
  componentName?: string;
  componentVersion?: string;
  componentPurl?: string;
  /** Only ever populated from trusted tool/intelligence data (§74). */
  fixedVersion?: string;
  dependencyScope?: "RUNTIME" | "DEVELOPMENT" | "TEST" | "PROVIDED" | "UNKNOWN";
  reachability?: "REACHABLE" | "NOT_REACHABLE" | "UNKNOWN" | "POTENTIAL_EXPOSURE";
  /** SonarQube security hotspots (§27): REVIEW_REQUIRED, never silently
   *  promoted to confirmed vulnerabilities. */
  reviewStatus?: "REVIEW_REQUIRED";
  /** True when the finding sits in generated code (§87) — reported with
   *  lower default priority, never silently dropped. */
  generatedCode?: boolean;
  /** Baseline classification against the previous snapshot (§79). */
  baselineStatus?: "NEW" | "EXISTING" | "RESOLVED";
  // ── Prompt 13 — cloud-native finding extensions (§51/§94). All
  // optional; populated only by container/Kubernetes adapters. Static
  // analysis and live observation are distinguished by `origin` and
  // correlated WITHOUT collapsing either observation (§51/§103).
  origin?: "STATIC_CONFIGURATION_FINDING" | "LIVE_CLUSTER_FINDING" | "IMAGE_FINDING" | "DOCKER_HOST_FINDING" | "RUNTIME_CORRELATED" | "CLOUD_FINDING";
  /** Image identity the finding is bound to — digest is strongest (§5). */
  imageDigest?: string;
  imageRef?: string;
  clusterRef?: string;
  namespace?: string;
  resourceKind?: string;
  resourceName?: string;
  containerName?: string;
  /** CIS / NSA-CISA control identifier for posture findings (§31/§41). */
  controlId?: string;
  /** Package origin inside an image (§21): OS packages vs language
   *  ecosystems are different remediation paths and never conflated. */
  packageType?: "OS" | "LANGUAGE" | "UNKNOWN";
  /** Image layer digest the component/vulnerability was seen in (§22). */
  layerDigest?: string;
  // ── Prompt 14 — multi-cloud finding extensions (§58/§61). All
  // optional; populated only by cloud-security analyzers/parsers.
  /** Cloud finding class (§58) — misconfigurations, IAM risks,
   *  exposure, gaps and vulnerabilities stay distinguishable. */
  findingClass?: CloudFindingClass;
  cloudProvider?: "AWS" | "AZURE" | "GCP";
  /** Registered CloudAccount id (platform identity, not a credential). */
  cloudAccountId?: string;
  /** Provider-native resource identity (ARN / resource id / full name). */
  providerResourceId?: string;
  cloudResourceType?: string;
  cloudRegion?: string;
  /** Evidence-based exposure verdict for the resource (§47). */
  exposureClass?: CloudExposureClass;
  // ── Prompt 15 — Active Directory finding extensions (§61/§67). All
  // optional; populated only by directory analyzers/parsers. Identity
  // metadata only — no credential material can ride on a finding (§19).
  /** Registered ActiveDirectoryDomain id (platform identity). */
  directoryDomainId?: string;
  /** Domain DNS name the finding belongs to (fingerprint component). */
  directoryDomainRef?: string;
  /** Directory object the finding concerns (SID / object id). */
  directoryObjectId?: string;
  /** Directory object kind: USER | GROUP | COMPUTER | GPO | CA | TEMPLATE | DOMAIN | DC. */
  directoryObjectType?: string;
}

/** Prompt 14 §58: cloud finding classes — kept distinguishable end to end. */
export type CloudFindingClass =
  | "CLOUD_MISCONFIGURATION" | "IAM_RISK" | "PUBLIC_EXPOSURE" | "ENCRYPTION_GAP"
  | "LOGGING_GAP" | "COMPLIANCE_FAILURE" | "POTENTIAL_VULNERABILITY" | "CONFIRMED_VULNERABILITY";

/** Prompt 14 §47: exposure classification — from evidence only, never
 *  fabricated reachability. */
export type CloudExposureClass = "PUBLIC" | "INTERNET_REACHABLE_POSSIBLE" | "PRIVATE" | "UNKNOWN";

/** A normalized cloud resource (Prompt 14 §14): bounded, security-
 *  relevant metadata only. Customer data inside resources — objects,
 *  secret values, key material — is never part of inventory (§13). */
export interface NormalizedCloudResource {
  provider: "AWS" | "AZURE" | "GCP";
  resourceType: string;
  providerResourceId: string;
  name: string;
  region?: string;
  zone?: string;
  /** Sanitized provider tags/labels (§99). */
  tags: Record<string, string>;
  /** Bounded normalized security configuration metadata (§14). */
  configuration: Record<string, unknown>;
  exposure: CloudExposureClass;
  criticality?: string;
  source: string; // adapter slug that reported it
}

/** A normalized cloud identity (Prompt 14 §36): users, roles, groups,
 *  service identities and policies with privilege/MFA/staleness
 *  METADATA only — credential material never exists here (§40). */
export interface NormalizedCloudIdentity {
  provider: "AWS" | "AZURE" | "GCP";
  identityType: "USER" | "ROLE" | "GROUP" | "SERVICE_ACCOUNT" | "MANAGED_IDENTITY" | "POLICY";
  providerIdentityId: string;
  name: string;
  privileged?: boolean;
  privilegeEvidence?: Record<string, unknown>;
  mfaEnabled?: boolean;
  lastUsedAt?: string;
  lastSignInAt?: string;
  keyAgeDays?: number;
  metadata: Record<string, unknown>;
}

/** An evidence-backed asset-graph edge (Prompt 14 §15/§37/§85). */
export interface NormalizedCloudRelationship {
  fromType: string;
  fromRef: string;
  toType: string;
  toRef: string;
  relationship: string;
  evidence?: string;
}

/** An inventory snapshot descriptor (Prompt 14 §19). */
export interface NormalizedCloudSnapshot {
  provider: "AWS" | "AZURE" | "GCP";
  regions: string[];
  resourceCounts: Record<string, number>;
  snapshotHash: string;
}

/** A defensive, evidence-backed risk path (Prompt 14 §66/§67). The
 *  path is modeled, never executed; confidence reflects graph evidence. */
export interface NormalizedCloudRiskPath {
  title: string;
  steps: { kind: string; ref: string; label: string }[];
  confidence: "LOW" | "MEDIUM" | "HIGH";
  findingFingerprints: string[];
}

/** The multi-cloud payload of a normalized result (Prompt 14). */
export interface NormalizedCloudData {
  resources: NormalizedCloudResource[];
  identities: NormalizedCloudIdentity[];
  relationships: NormalizedCloudRelationship[];
  controlAssessments: NormalizedControlAssessment[];
  snapshot?: NormalizedCloudSnapshot;
  riskPaths: NormalizedCloudRiskPath[];
  /** Resources the account scope excluded (§15): recorded with an
   *  OUT_OF_SCOPE verdict, never analyzed, never promoted. */
  outOfScopeResources?: NormalizedCloudResource[];
}

/** Prompt 15 §19: a directory user — security-relevant METADATA only.
 *  There is deliberately no field that could hold a password or hash. */
export interface NormalizedDirectoryUser {
  objectId: string; // SID / objectGUID
  samAccountName: string;
  displayName?: string;
  userPrincipalName?: string;
  enabled: boolean;
  isServiceAccount?: boolean;
  passwordNeverExpires?: boolean;
  passwordNotRequired?: boolean;
  /** DONT_REQUIRE_PREAUTH — Kerberos posture METADATA (§57). The
   *  platform analyzes the flag; it never requests roastable material. */
  preauthNotRequired?: boolean;
  spnPresent?: boolean;
  spns?: string[];
  delegationType?: "NONE" | "UNCONSTRAINED" | "CONSTRAINED" | "RESOURCE_BASED";
  delegationTargets?: string[];
  lastLogonAt?: string;
  passwordLastSetAt?: string;
}

/** Prompt 15 §20: a directory computer, linkable to a network Asset. */
export interface NormalizedDirectoryComputer {
  objectId: string;
  hostname: string;
  dnsName?: string;
  osName?: string;
  osVersion?: string;
  enabled: boolean;
  isDomainController?: boolean;
  delegationType?: "NONE" | "UNCONSTRAINED" | "CONSTRAINED" | "RESOURCE_BASED";
  delegationTargets?: string[];
  ipAddresses?: string[];
}

/** Prompt 15 §6: a domain controller + its service posture metadata. */
export interface NormalizedDomainController {
  hostname: string;
  dnsName?: string;
  ipAddresses: string[];
  osName?: string;
  osVersion?: string;
  objectId?: string;
  /** LDAP/LDAPS/SMB/Kerberos/DNS/GC presence + posture facts (§70/§71):
   *  ldapPresent, ldapsPresent, ldapSigningRequired, channelBinding,
   *  smbSigningRequired, smb1Enabled — metadata only. */
  services: Record<string, unknown>;
}

/** Prompt 15 §21/§22: a directory group with SID-based privilege class. */
export interface NormalizedDirectoryGroup {
  objectId: string; // SID
  name: string;
  groupScope?: "GLOBAL" | "UNIVERSAL" | "DOMAIN_LOCAL";
  groupType?: "SECURITY" | "DISTRIBUTION";
  privilegeClass: "PRIVILEGED" | "HIGH_IMPACT" | "STANDARD";
  memberCount?: number;
}

/** Prompt 15 §23: an organizational unit. */
export interface NormalizedDirectoryOU {
  objectId: string;
  name: string;
  distinguishedName: string;
  parentRef?: string;
  linkedGpoIds: string[];
}

/** Prompt 15 §24: a Group Policy Object — metadata only, never modified. */
export interface NormalizedDirectoryGpo {
  objectId: string;
  name: string;
  linkedTo: string[];
  securityMetadata: Record<string, unknown>;
  delegationMetadata: Record<string, unknown>;
  lastModifiedAt?: string;
}

/** Prompt 15 §25: a directory trust. */
export interface NormalizedDirectoryTrust {
  targetDomainName: string;
  targetDomainSid?: string;
  direction: "INBOUND" | "OUTBOUND" | "BIDIRECTIONAL";
  trustType: "FOREST" | "EXTERNAL" | "PARENT_CHILD" | "SHORTCUT" | "UNKNOWN";
  transitive: boolean;
  sidFilteringEnabled?: boolean;
  selectiveAuthentication?: boolean;
}

/** Prompt 15 §32/§33: an identity-graph edge. Only edges the collected
 *  evidence supports exist; every edge carries provenance. */
export interface NormalizedDirectoryRelationship {
  fromType: string; // USER | GROUP | COMPUTER | DOMAIN | OU | GPO | CERTIFICATE_AUTHORITY | CERTIFICATE_TEMPLATE | SERVICE_ACCOUNT
  fromRef: string;
  toType: string;
  toRef: string;
  relationship: string; // MEMBER_OF | ADMIN_TO | HAS_SESSION | CAN_RDP | CAN_REMOTE_MANAGE | OWNS | GENERIC_ALL | GENERIC_WRITE | WRITE_DACL | WRITE_OWNER | GPO_LINK | TRUST | DELEGATION
  source: string; // adapter slug that reported the edge
  confidence: "LOW" | "MEDIUM" | "HIGH";
  evidenceRef?: string;
}

/** Prompt 15 §42: an SMB share observation — inventory only, contents
 *  are never downloaded. */
export interface NormalizedSmbShare {
  host: string;
  shareName: string;
  accessLevel: "NONE" | "READ" | "READ_WRITE" | "ADMIN" | "UNKNOWN";
  anonymousAccess?: boolean;
  smbDialect?: string;
  signingRequired?: boolean;
  source: string;
}

/** Prompt 15 §46: an AD CS certificate authority. */
export interface NormalizedCertificateAuthority {
  name: string;
  dnsName?: string;
  enrollmentServices: string[];
  metadata: Record<string, unknown>;
}

/** Prompt 15 §46/§49: a certificate template + its governed risk
 *  classes (§50) — analysis labels only, never exploited. */
export interface NormalizedCertificateTemplate {
  name: string;
  objectId?: string;
  caName?: string;
  enabled?: boolean;
  enrollmentPermissions: Record<string, unknown>;
  subjectConfig: Record<string, unknown>;
  authenticationEkus: string[];
  managerApprovalRequired?: boolean;
  authorizedSignaturesRequired?: number;
  issuanceRequirements: Record<string, unknown>;
  riskClasses: string[];
}

/** Prompt 15 §18: a directory snapshot descriptor — the drift baseline. */
export interface NormalizedDirectorySnapshot {
  collectionProfile: string;
  collectorVersions: Record<string, string>;
  objectCounts: Record<string, number>;
  relationshipCount: number;
  snapshotHash: string;
}

/** Prompt 15 §4/§5: the domain/forest identity of a collection. */
export interface NormalizedDirectoryDomainInfo {
  dnsName: string;
  netbiosName?: string;
  domainSid?: string;
  functionalLevel?: string;
  forestRootDomain?: string;
}

/** The Active Directory payload of a normalized result (Prompt 15). */
export interface NormalizedDirectoryData {
  domain?: NormalizedDirectoryDomainInfo;
  domainControllers: NormalizedDomainController[];
  users: NormalizedDirectoryUser[];
  groups: NormalizedDirectoryGroup[];
  computers: NormalizedDirectoryComputer[];
  organizationalUnits: NormalizedDirectoryOU[];
  groupPolicies: NormalizedDirectoryGpo[];
  trusts: NormalizedDirectoryTrust[];
  relationships: NormalizedDirectoryRelationship[];
  smbShares: NormalizedSmbShare[];
  certificateAuthorities: NormalizedCertificateAuthority[];
  certificateTemplates: NormalizedCertificateTemplate[];
  snapshot?: NormalizedDirectorySnapshot;
  /** Domain password-policy metadata (§60) for the posture analyzers. */
  passwordPolicy?: Record<string, unknown>;
}

/** A container image observed by an image/SBOM scan (Prompt 13 §5/§13):
 *  identity + static metadata only. Images are NEVER executed (§9), so
 *  no runtime state exists in this record. */
export interface NormalizedContainerImage {
  /** Full reference as observed (registry/repository[:tag][@digest]). */
  reference?: string;
  registry: string;
  repository: string;
  tag?: string;
  digest?: string;
  platform?: string;
  architecture?: string;
  os?: string;
  source: string;
  config?: { user?: string; exposedPorts: string[]; entrypointPresent: boolean; cmdPresent: boolean; envKeys: string[]; labels: Record<string, string> };
  layers?: { digest: string; sizeBytes?: number }[];
  baseImage?: { registry: string; repository: string; digest?: string };
}

/** A Kubernetes workload from cluster inventory (Prompt 13 §37/§38).
 *  Security context is a SUMMARY of posture-relevant booleans/values;
 *  Secret values are never part of inventory (§36/§105). */
export interface NormalizedKubernetesWorkload {
  clusterRef: string;
  kind: string;
  namespace: string;
  name: string;
  replicas?: number;
  serviceAccount?: string;
  images: { container: string; image: string; digest?: string; tagPinned: boolean; digestPinned: boolean }[];
  securityContext: {
    privileged?: boolean;
    runAsRoot?: boolean;
    allowPrivilegeEscalation?: boolean;
    readOnlyRootFilesystem?: boolean;
    hostNetwork?: boolean;
    hostPid?: boolean;
    hostIpc?: boolean;
    hostPaths: string[];
    addedCapabilities: string[];
    automountServiceAccountToken?: boolean;
    resourceLimitsDeclared?: boolean;
  };
  exposure: "PUBLIC_INTERNET" | "EXTERNAL_NETWORK" | "CLUSTER_INTERNAL" | "LOCAL_ONLY" | "UNKNOWN";
  labels: Record<string, string>;
}

/** One compliance control evaluation (Prompt 13 §56). PASS results are
 *  posture evidence, never findings. */
export interface NormalizedControlAssessment {
  frameworkKey: string; // CIS_DOCKER | CIS_KUBERNETES | NSA_CISA_KUBERNETES
  controlId: string;
  subjectRef: string;
  status: "PASS" | "FAIL" | "WARN" | "NOT_APPLICABLE" | "UNKNOWN";
  evidence: string;
}

/** A static infrastructure manifest under analysis (Prompt 13 §48). */
export interface NormalizedInfrastructureManifest {
  filePath: string;
  manifestType: "DOCKERFILE" | "KUBERNETES" | "HELM_CHART" | "HELM_VALUES" | "COMPOSE";
  resourceCount: number;
  checksum: string;
}

/** A normalized runtime security event (Prompt 13 §59/§60): sanitized
 *  sensor metadata. Events are detections, not vulnerabilities (§63). */
export interface NormalizedRuntimeEvent {
  clusterName?: string;
  node?: string;
  namespace?: string;
  pod?: string;
  container?: string;
  rule: string;
  priority: string;
  eventTime: string; // ISO
  metadata: Record<string, string>;
  source: string;
}

/** The cloud-native payload of a normalized result (Prompt 13). */
export interface NormalizedCloudNativeData {
  images: NormalizedContainerImage[];
  workloads: NormalizedKubernetesWorkload[];
  controlAssessments: NormalizedControlAssessment[];
  manifests: NormalizedInfrastructureManifest[];
  runtimeEvents: NormalizedRuntimeEvent[];
}

/** Secret finding metadata (Prompt 12 §40/§43) — the ONLY representation
 *  of a detected secret anywhere in the platform. There is deliberately
 *  no field capable of holding the raw value. */
export interface NormalizedSecretFinding {
  secretType: string;
  /** Detector / rule that matched (e.g. gitleaks rule id). */
  detector: string;
  /** One-way fingerprint (HMAC-SHA256 when keyed, §41). */
  fingerprint: string;
  /** Redacted preview like `AKIA…MPLE` — first/last fragments only, and
   *  only when the value is long enough that fragments cannot reveal it. */
  redactedPreview?: string;
  commitSha?: string;
  verificationStatus: "NOT_VERIFIED" | "VERIFIED_ACTIVE" | "VERIFIED_INACTIVE" | "VERIFICATION_FAILED";
}

/** A software component identified from manifests/lockfiles or scanner
 *  output (Prompt 12 §45) — the dependency-inventory record SCA and SBOM
 *  generation build on. */
export interface NormalizedSoftwareComponent {
  name: string;
  version?: string;
  ecosystem: string;
  /** Package URL (§46) — the component identity used for correlation. */
  purl: string;
  /** Repository-relative manifest/lockfile the component came from. */
  sourceManifest: string;
  /** DIRECT = declared by the project; TRANSITIVE = pulled in (§45). */
  scope: "DIRECT" | "TRANSITIVE" | "UNKNOWN";
  dependencyScope: "RUNTIME" | "DEVELOPMENT" | "TEST" | "PROVIDED" | "UNKNOWN";
  licenses: string[];
  supplier?: string;
  description?: string;
}

/** A generated SBOM document (Prompt 12 §47/§48): the document itself
 *  lives in object storage behind `artifactRef`; this record carries the
 *  format, checksum and component count only. */
export interface NormalizedSbom {
  format: "CYCLONEDX_JSON" | "SPDX_JSON" | "SPDX_TAG_VALUE";
  specVersion: string;
  checksum: string;
  componentCount: number;
  artifactRef?: string;
  /** The serialized document (fixture/in-process flows only; persisted
   *  flows store it as an artifact and keep the reference). */
  document?: string;
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
  /** Software components inventoried by source scans (Prompt 12 §45). */
  components?: NormalizedSoftwareComponent[];
  /** SBOM generated by a source scan (Prompt 12 §47). */
  sbom?: NormalizedSbom;
  /** Container / Kubernetes inventory + posture payload (Prompt 13). */
  cloudNative?: NormalizedCloudNativeData;
  /** Multi-cloud inventory + IAM + posture payload (Prompt 14). */
  cloud?: NormalizedCloudData;
  /** Active Directory inventory + identity graph payload (Prompt 15). */
  directory?: NormalizedDirectoryData;
  artifacts: import("../artifacts/artifact.types").ArtifactMetadata[];
  metrics: Record<string, number>;
  /** True when produced by the Mock adapter — fixture data, NOT real results. */
  mock: boolean;
}
