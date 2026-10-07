import {
  canonicalizeHostname, canonicalizeUrl, classifyApiKind, classifyEndpointType, computeRisk, correlateFindings as sdkCorrelateFindings,
  correlateSourceFindings, detectCrawlerTrap, detectWildcardGroups,
  endpointIdentityKey, extractParameterNames, findingFingerprint, iacLiveMatchKey, liveMatchKey, redactUrl, sameConfigurationIdentity, sensitiveRouteLabel,
  sourceRiskFactors,
  ScopeMatcher, type CorrelationStats, type DnsRecordSet, type NormalizedFinding,
  type NormalizedSecurityResult, type NormalizedSoftwareComponent, type NormalizedVulnFinding,
} from "@dsrclone/security-sdk";
import type { ScopeRules } from "@dsrclone/validation";

/**
 * Result processing (Prompt 4 §32–§37, extended by Prompt 5 §31–§36):
 * normalized results — and ONLY normalized results — become persistence
 * records. Tool-specific output never leaks into core logic. Discovered
 * assets are canonicalized, deduplicated (provenance preserved as sources)
 * and scope-checked; out-of-scope assets are kept for visibility with an
 * OUT_OF_SCOPE verdict and never become scan targets. Endpoints are stored
 * with parameter NAMES only and sensitive parameter values redacted (§22);
 * services and technologies become inventory rows (§32–§34).
 */
export interface ProcessedAsset {
  host: string;
  ip?: string;
  type: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE" | "PENDING_REVIEW";
  sources: string[];
  dnsRecords?: DnsRecordSet[];
  httpStatus?: number;
  wildcardSuspect?: boolean;
  /** Prompt 10 §35/§50: OS hint + confidence and the owning network —
   *  hints only, never presented as fact. */
  osHint?: string;
  osConfidence?: number;
  network?: string;
}

export interface ProcessedEndpoint {
  url: string;
  method: string;
  statusCode?: number;
  parameterNames: string[];
  source?: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE";
  /** Prompt 6 §16/§26/§41–§42: safe response metadata + route labels. */
  contentType?: string;
  contentLength?: number;
  title?: string;
  redirectLocation?: string;
  endpointType: string;
  classification?: string;
  sources: string[];
  wildcardSuspect?: boolean;
}

/** Prompt 6 §27: parameter NAMES + provenance only — values never persist. */
export interface ProcessedParameter {
  endpointUrl: string;
  name: string;
  location: string;
  sources: string[];
  confidence?: number;
}

/** Prompt 6 §33: form structure metadata. */
export interface ProcessedForm {
  endpointUrl: string;
  method: string;
  fieldNames: string[];
  encodingType?: string;
  source?: string;
}

export interface ProcessedService {
  host: string;
  port: number;
  protocol: string;
  name: string;
  product?: string;
  version?: string;
  statusCode?: number;
  title?: string;
  server?: string;
  scheme?: string;
  /** Prompt 10 §29–§36/§49: network facts — port state, CPE (only when
   *  a tool reported it), SANITIZED banner, TLS flag, identification
   *  confidence and aggregator provenance. */
  state?: string;
  cpe?: string;
  banner?: string;
  tls?: boolean;
  confidence?: number;
  sources?: string[];
}

/** Prompt 10 §43: packet-capture metadata passthrough — bytes stay in
 *  object storage; only the reference + facts persist. */
export interface ProcessedPacketCapture {
  artifactRef: string;
  format: string;
  source: string;
  sizeBytes?: number;
  sha256?: string;
  durationSeconds?: number;
  interfaceName?: string;
  assetHost?: string;
}

export interface ProcessedTechnology {
  host?: string;
  name: string;
  version?: string;
  category?: string;
  source?: string;
  confidence?: number;
}

export interface ProcessedEvidence {
  sourceTool: string;
  summary: string;
  fingerprint?: string;
  matchedAt?: string;
  metadata?: Record<string, unknown>;
}

export interface ProcessedReference {
  type: string;
  label: string;
  url: string;
}

export interface ProcessedFinding {
  title: string;
  description: string;
  severity: string;
  confidence: number;
  host?: string;
  endpoint?: string;
  fingerprint: string;
  isMock: boolean;
  sourceTool: string;
  toolExecutionId: string;
  evidenceSummary: string;
  /** Prompt 7 rich normalization (§16/§17): carried ONLY when the tool
   *  output or the curated taxonomy provides them — never invented. */
  vulnClass?: string;
  sources: string[];
  evidenceRows: ProcessedEvidence[];
  references: ProcessedReference[];
  cve?: string;
  cwe?: string;
  owaspCategory?: string;
  cvssScore?: number;
  cvssVector?: string;
  port?: number;
  protocol?: string;
  parameter?: string;
  technicalImpact?: string;
  businessImpact?: string;
  remediation?: string;
  /** Risk-engine output, filled by the CORRELATION stage (§34/§35). */
  riskScore?: number;
  riskBand?: string;
  riskExplanation?: string[];
  confidenceBand?: string;
  verificationStatus?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
  /** Prompt 12 §59: source-code location + dependency extensions —
   *  repository-relative paths only, redacted snippets in evidence. */
  filePath?: string;
  startLine?: number;
  endLine?: number;
  startColumn?: number;
  endColumn?: number;
  ruleId?: string;
  codeFlow?: { label: string; filePath: string; startLine?: number; endLine?: number }[];
  secret?: import("@dsrclone/security-sdk").NormalizedSecretFinding;
  componentName?: string;
  componentVersion?: string;
  componentPurl?: string;
  fixedVersion?: string;
  dependencyScope?: string;
  reachability?: string;
  reviewStatus?: string;
  generatedCode?: boolean;
  baselineStatus?: string;
  /** Prompt 13 §51/§94: cloud-native identity — origin distinguishes
   *  static configuration analysis from live cluster observation;
   *  correlation preserves both observations (§103). */
  origin?: string;
  imageDigest?: string;
  imageRef?: string;
  clusterRef?: string;
  namespace?: string;
  resourceKind?: string;
  resourceName?: string;
  containerName?: string;
  controlId?: string;
  packageType?: string;
  layerDigest?: string;
  /** Prompt 14 §58/§61: multi-cloud identity — provider, account,
   *  resource and finding class ride along so cloud findings persist
   *  with their full identity and correlate on cloud fingerprints. */
  findingClass?: string;
  cloudProvider?: string;
  cloudAccountId?: string;
  providerResourceId?: string;
  cloudResourceType?: string;
  cloudRegion?: string;
  exposureClass?: string;
}

/** Prompt 12 §45: component inventory passthrough (PURL identity). */
export type ProcessedComponent = NormalizedSoftwareComponent;

/** Prompt 14 §14/§15: a normalized cloud resource plus its scope
 *  verdict — out-of-scope resources are recorded, never analyzed. */
export type ProcessedCloudResource = import("@dsrclone/security-sdk").NormalizedCloudResource & {
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE";
};

/** Prompt 8 §25/§26: observed HTTP traffic — metadata, hashes, sizes,
 *  artifact references and REDACTED display copies. Raw bodies never
 *  appear here; they live in the execution's raw artifact in object
 *  storage, and the refs point into it. */
export interface ProcessedTransaction {
  method: string;
  url: string;
  host: string;
  statusCode?: number;
  source: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE";
  apiKind?: string;
  requestHash?: string;
  responseHash?: string;
  requestSize?: number;
  responseSize?: number;
  requestArtifactRef?: string;
  responseArtifactRef?: string;
  requestRedacted?: string;
  responseRedacted?: string;
  observedAt?: string;
}

/** Prompt 8 §49: WebSocket inventory (no attack automation). */
export interface ProcessedWebSocket {
  url: string;
  origin?: string;
  subprotocol?: string;
  source: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE";
  /** Prompt 9 §32: authentication material presence on the handshake. */
  authPresent?: boolean;
}

/** Prompt 9 §3/§37: API service inventory with a scope verdict. */
export interface ProcessedApiService {
  baseUrl: string;
  host: string;
  apiType: string;
  version?: string;
  authenticationType?: string;
  specificationId?: string;
  source: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE";
}

/** Prompt 9 §26: GraphQL service inventory with a scope verdict. */
export interface ProcessedGraphqlService {
  endpointUrl: string;
  host: string;
  schemaAvailable: boolean;
  queries: number;
  mutations: number;
  subscriptions: number;
  types: number;
  authenticationRequired?: boolean;
  source: string;
  scopeStatus: "IN_SCOPE" | "OUT_OF_SCOPE";
}

/** Prompt 9 §25: JWT inspection metadata — fingerprint + redacted claims
 *  only; a raw token can never reach this shape. */
export type ProcessedJwtProfile = import("@dsrclone/security-sdk").NormalizedJwtProfile;

export interface ProcessedResult {
  assets: ProcessedAsset[];
  endpoints: ProcessedEndpoint[];
  services: ProcessedService[];
  technologies: ProcessedTechnology[];
  findings: ProcessedFinding[];
  /** Prompt 9: API + GraphQL inventory and JWT inspection metadata. */
  apiServices: ProcessedApiService[];
  graphqlServices: ProcessedGraphqlService[];
  jwtProfiles: ProcessedJwtProfile[];
  /** Prompt 8: proxy-observed traffic + WebSocket inventory. */
  transactions: ProcessedTransaction[];
  webSockets: ProcessedWebSocket[];
  /** Prompt 10: packet-capture artifact metadata (§43). */
  packetCaptures: ProcessedPacketCapture[];
  /** Prompt 12: software components inventoried by source scans (§45). */
  components: ProcessedComponent[];
  /** Prompt 13: cloud-native inventory + posture payload passthrough. */
  cloudNative: import("@dsrclone/security-sdk").NormalizedCloudNativeData;
  /** Prompt 14: multi-cloud inventory payload passthrough — resources
   *  carry their scope verdict (§15); the stores persist them. */
  cloud: {
    resources: ProcessedCloudResource[];
    identities: import("@dsrclone/security-sdk").NormalizedCloudIdentity[];
    relationships: import("@dsrclone/security-sdk").NormalizedCloudRelationship[];
    controlAssessments: import("@dsrclone/security-sdk").NormalizedControlAssessment[];
    riskPaths: import("@dsrclone/security-sdk").NormalizedCloudRiskPath[];
    snapshot?: import("@dsrclone/security-sdk").NormalizedCloudSnapshot;
  };
  /** Prompt 6: parameter + form inventory, and how many candidate
   *  endpoints were suppressed by the wildcard/trap guards (§19/§47). */
  parameters: ProcessedParameter[];
  forms: ProcessedForm[];
  suppressedEndpoints: number;
  isMock: boolean;
}

export function canonicalHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

function mergeDns(a: DnsRecordSet[] | undefined, b: DnsRecordSet[] | undefined): DnsRecordSet[] | undefined {
  if (!b?.length) return a;
  if (!a?.length) return b;
  const byType = new Map<string, Set<string>>();
  for (const rec of [...a, ...b]) {
    const set = byType.get(rec.type) ?? new Set<string>();
    for (const v of rec.values) set.add(v);
    byType.set(rec.type, set);
  }
  return [...byType.entries()].map(([type, values]) => ({ type, values: [...values].sort() }));
}

export function processNormalizedResult(
  result: NormalizedSecurityResult,
  ctx: { scopeRules: ScopeRules; toolExecutionId: string; toolSlug?: string; artifactKey?: string },
): ProcessedResult {
  const matcher = new ScopeMatcher(ctx.scopeRules);
  const tool = ctx.toolSlug ?? "unknown";

  // --- services first: asset HTTP status is derived from them (§32) ---
  const services: ProcessedService[] = [];
  const serviceKeys = new Set<string>();
  const httpStatusByHost = new Map<string, number>();
  for (const svc of result.services) {
    const host = canonicalizeHostname(svc.host) ?? canonicalHost(svc.host);
    if (!host) continue;
    const key = `${host}|${svc.port}|${svc.protocol}`;
    if (serviceKeys.has(key)) {
      // Same-key duplicate inside one result: gap-fill descriptive
      // fields (PortResultAggregator semantics, §49) instead of dropping.
      const existingSvc = services.find((s) => `${s.host}|${s.port}|${s.protocol}` === key)!;
      existingSvc.product ??= svc.product;
      existingSvc.version ??= svc.version;
      existingSvc.cpe ??= svc.cpe;
      existingSvc.banner ??= svc.banner;
      existingSvc.sources = [...new Set([...(existingSvc.sources ?? []), ...(svc.sources ?? [])])];
      continue;
    }
    serviceKeys.add(key);
    services.push({
      host, port: svc.port, protocol: svc.protocol,
      name: svc.name ?? svc.scheme ?? "unknown",
      ...(svc.product ? { product: svc.product } : {}),
      ...(svc.version ? { version: svc.version } : {}),
      ...(svc.statusCode !== undefined ? { statusCode: svc.statusCode } : {}),
      ...(svc.title ? { title: svc.title } : {}),
      ...(svc.server ? { server: svc.server } : {}),
      ...(svc.scheme ? { scheme: svc.scheme } : {}),
      ...(svc.state ? { state: svc.state } : {}),
      ...(svc.cpe ? { cpe: svc.cpe } : {}),
      ...(svc.banner ? { banner: svc.banner } : {}),
      ...(svc.tls !== undefined ? { tls: svc.tls } : {}),
      ...(svc.confidence !== undefined ? { confidence: svc.confidence } : {}),
      ...(svc.sources?.length ? { sources: [...new Set(svc.sources)] } : {}),
    });
    if (svc.statusCode !== undefined && !httpStatusByHost.has(host)) httpStatusByHost.set(host, svc.statusCode);
  }

  // --- assets: canonical, deduped, provenance merged, scope verdicts ---
  const assetByHost = new Map<string, ProcessedAsset>();
  for (const asset of result.assets) {
    const host = canonicalizeHostname(asset.host) ?? canonicalHost(asset.host);
    if (!host) continue;
    const existing = assetByHost.get(host);
    if (existing) {
      for (const s of asset.sources ?? []) if (!existing.sources.includes(s)) existing.sources.push(s);
      if (!existing.ip && asset.ip) existing.ip = asset.ip;
      if (asset.wildcardSuspect) existing.wildcardSuspect = true;
      existing.dnsRecords = mergeDns(existing.dnsRecords, asset.dnsRecords);
      if (!existing.osHint && asset.osHint) { existing.osHint = asset.osHint; existing.osConfidence = asset.osConfidence; }
      if (!existing.network && asset.network) existing.network = asset.network;
      continue;
    }
    const verdict = matcher.isDiscoveredAssetInScope(host);
    assetByHost.set(host, {
      host,
      ip: asset.ip,
      type: asset.type,
      scopeStatus: verdict.allowed ? "IN_SCOPE" : "OUT_OF_SCOPE",
      sources: [...new Set([tool, ...(asset.sources ?? [])])],
      ...(asset.dnsRecords ? { dnsRecords: asset.dnsRecords } : {}),
      ...(asset.wildcardSuspect ? { wildcardSuspect: true } : {}),
      ...(asset.osHint ? { osHint: asset.osHint, ...(asset.osConfidence !== undefined ? { osConfidence: asset.osConfidence } : {}) } : {}),
      ...(asset.network ? { network: asset.network } : {}),
    });
  }
  const assets = [...assetByHost.values()];
  for (const a of assets) {
    const status = httpStatusByHost.get(a.host);
    if (status !== undefined) a.httpStatus = status;
  }

  // --- endpoints: canonical, deduped by method+origin+path, params merged,
  //     values of sensitive parameters redacted before storage (§22).
  //     Prompt 6 guards run BEFORE dedupe: identical-fingerprint wildcard
  //     shells collapse to one flagged representative (§19) and
  //     trap-shaped URLs never become inventory (§47). Classification and
  //     provenance (sources) are attached here (§26/§41–§42). ---
  let suppressedEndpoints = 0;
  const { kept: wildcardKept, groups: wildcardGroups } = detectWildcardGroups(result.endpoints);
  const wildcardRepresentatives = new Set(wildcardGroups.map((g) => g.representative.url));
  suppressedEndpoints += wildcardGroups.reduce((n, g) => n + g.collapsed.length, 0);
  const endpointByKey = new Map<string, ProcessedEndpoint>();
  const addEndpoint = (ep: { url: string; method?: string; statusCode?: number; parameterNames?: string[]; source?: string; sources?: string[]; contentType?: string; contentLength?: number; title?: string; redirectLocation?: string; endpointType?: string; classification?: string; fingerprint?: string; wildcardSuspect?: boolean }): void => {
    const canonical = canonicalizeUrl(ep.url);
    if (!canonical) return;
    if (detectCrawlerTrap(canonical).trap) { suppressedEndpoints++; return; }
    const method = (ep.method ?? "GET").toUpperCase();
    const key = endpointIdentityKey(method, canonical);
    const existing = endpointByKey.get(key);
    if (existing) {
      existing.parameterNames = [...new Set([...existing.parameterNames, ...(ep.parameterNames ?? extractParameterNames(canonical))])].sort();
      existing.sources = [...new Set([...existing.sources, ...(ep.sources ?? [ep.source ?? tool])])].sort();
      if (existing.statusCode === undefined && ep.statusCode !== undefined) existing.statusCode = ep.statusCode;
      if (!existing.contentType && ep.contentType) existing.contentType = ep.contentType;
      if (existing.contentLength === undefined && ep.contentLength !== undefined) existing.contentLength = ep.contentLength;
      if (!existing.redirectLocation && ep.redirectLocation) existing.redirectLocation = ep.redirectLocation;
      return;
    }
    endpointByKey.set(key, {
      url: redactUrl(canonical),
      method,
      ...(ep.statusCode !== undefined ? { statusCode: ep.statusCode } : {}),
      parameterNames: ep.parameterNames ?? extractParameterNames(canonical),
      ...(ep.source ?? tool ? { source: ep.source ?? tool } : {}),
      scopeStatus: matcher.isUrlAllowed(canonical) ? "IN_SCOPE" : "OUT_OF_SCOPE",
      ...(ep.contentType ? { contentType: ep.contentType } : {}),
      ...(ep.contentLength !== undefined ? { contentLength: ep.contentLength } : {}),
      ...(ep.title ? { title: ep.title } : {}),
      ...(ep.redirectLocation ? { redirectLocation: ep.redirectLocation } : {}),
      endpointType: ep.endpointType ?? classifyEndpointType(canonical),
      ...(ep.classification ?? sensitiveRouteLabel(canonical) ? { classification: ep.classification ?? sensitiveRouteLabel(canonical) } : {}),
      sources: [...new Set([tool, ...(ep.sources ?? [ep.source ?? tool])])].sort(),
      ...(wildcardRepresentatives.has(ep.url) || ep.wildcardSuspect ? { wildcardSuspect: true } : {}),
    });
  };
  for (const ep of wildcardKept) addEndpoint(ep);
  // §30: out-of-scope redirect targets become endpoint REFERENCES only.
  for (const svc of result.services) {
    if (!svc.redirectLocation) continue;
    const target = canonicalizeUrl(svc.redirectLocation);
    const fromHost = canonicalizeHostname(svc.host) ?? canonicalHost(svc.host);
    if (target && new URL(target).hostname !== fromHost) addEndpoint({ url: target });
  }
  const endpoints = [...endpointByKey.values()];

  // --- parameters (Prompt 6 §27/§30): deduped per endpoint+name+location
  //     with unioned provenance; attached ONLY to in-scope endpoints —
  //     out-of-scope parameters are dropped, never persisted (§28/§40). ---
  const inScopeEndpointUrls = new Set(endpoints.filter((e) => e.scopeStatus === "IN_SCOPE").flatMap((e) => [e.url, e.url.split("?")[0]!]));
  const parameterByKey = new Map<string, ProcessedParameter>();
  for (const param of result.parameters ?? []) {
    const canonical = canonicalizeUrl(param.endpointUrl);
    if (!canonical) continue;
    const base = canonical.split("?")[0]!;
    if (!inScopeEndpointUrls.has(redactUrl(base))) continue;
    const key = `${base}|${param.name}|${param.location}`;
    const existingParam = parameterByKey.get(key);
    if (existingParam) {
      existingParam.sources = [...new Set([...existingParam.sources, ...(param.sources ?? [tool])])].sort();
      existingParam.confidence = Math.max(existingParam.confidence ?? 0, param.confidence ?? 0) || undefined;
      continue;
    }
    parameterByKey.set(key, {
      endpointUrl: base, name: param.name, location: param.location,
      sources: [...new Set(param.sources ?? [tool])].sort(),
      ...(param.confidence !== undefined ? { confidence: param.confidence } : {}),
    });
  }
  const parameters = [...parameterByKey.values()];

  // --- forms (§33): structure metadata deduped per endpoint+method ---
  const formByKey = new Map<string, ProcessedForm>();
  for (const form of result.forms ?? []) {
    const canonical = canonicalizeUrl(form.endpointUrl);
    if (!canonical) continue;
    const key = `${canonical}|${form.method.toUpperCase()}`;
    const existingForm = formByKey.get(key);
    if (existingForm) {
      existingForm.fieldNames = [...new Set([...existingForm.fieldNames, ...form.fieldNames])].sort();
      continue;
    }
    formByKey.set(key, {
      endpointUrl: redactUrl(canonical), method: form.method.toUpperCase(),
      fieldNames: [...new Set(form.fieldNames)].sort(),
      ...(form.encodingType ? { encodingType: form.encodingType } : {}),
      ...(form.source ? { source: form.source } : {}),
    });
  }
  const forms = [...formByKey.values()];

  // --- technologies: deduped per host+name (§34) ---
  const techByKey = new Map<string, ProcessedTechnology>();
  for (const tech of result.technologies) {
    const host = tech.host ? canonicalizeHostname(tech.host) ?? canonicalHost(tech.host) : undefined;
    const key = `${host ?? ""}|${tech.name.toLowerCase()}`;
    const existing = techByKey.get(key);
    if (existing) {
      if (!existing.version && tech.version) existing.version = tech.version;
      if ((tech.confidence ?? 0) > (existing.confidence ?? 0)) existing.confidence = tech.confidence;
      continue;
    }
    techByKey.set(key, {
      ...(host ? { host } : {}), name: tech.name,
      ...(tech.version ? { version: tech.version } : {}),
      ...(tech.category ? { category: tech.category } : {}),
      ...(tech.source ? { source: tech.source } : {}),
      ...(tech.confidence !== undefined ? { confidence: tech.confidence } : {}),
    });
  }

  const findings: ProcessedFinding[] = result.findings.map((f) => {
    const v = f as NormalizedFinding & Partial<NormalizedVulnFinding>;
    return {
      title: f.title,
      description: f.description,
      severity: f.severity,
      confidence: f.confidence,
      host: f.host,
      endpoint: f.endpoint,
      fingerprint: f.sourceFingerprint && f.sourceFingerprint !== "mock-fixture"
        ? f.sourceFingerprint
        : findingFingerprint({ toolFamily: f.sourceTool, asset: f.host ?? "unknown", endpoint: f.endpoint, vulnClass: f.title }),
      isMock: result.mock,
      sourceTool: f.sourceTool,
      toolExecutionId: ctx.toolExecutionId,
      evidenceSummary: f.evidence ?? "",
      ...(v.vulnClass ? { vulnClass: v.vulnClass } : {}),
      sources: [f.sourceTool],
      evidenceRows: [{
        sourceTool: f.sourceTool,
        summary: f.evidence ?? "",
        ...(f.sourceFingerprint ? { fingerprint: f.sourceFingerprint } : {}),
        ...(v.evidenceDetail?.matchedAt ? { matchedAt: v.evidenceDetail.matchedAt } : {}),
        ...(v.evidenceDetail ? {
          metadata: {
            ...(v.evidenceDetail.checkId ? { checkId: v.evidenceDetail.checkId } : {}),
            ...(v.evidenceDetail.signatureFamily ? { signatureFamily: v.evidenceDetail.signatureFamily } : {}),
            ...(v.evidenceDetail.request ? { request: v.evidenceDetail.request } : {}),
            ...(v.evidenceDetail.response ? { response: v.evidenceDetail.response } : {}),
            ...(v.evidenceDetail.metadata ?? {}),
          },
        } : {}),
      }],
      references: (v.referencesDetailed ?? f.references.map((url) => ({ type: "OTHER", label: url, url }))).map((r) => ({ type: r.type, label: r.label, url: r.url })),
      ...(v.cve ? { cve: v.cve } : {}),
      ...(v.cwe ? { cwe: v.cwe } : {}),
      ...(v.owaspCategory ? { owaspCategory: v.owaspCategory } : {}),
      ...(v.cvssScore !== undefined ? { cvssScore: v.cvssScore } : {}),
      ...(v.cvssVector ? { cvssVector: v.cvssVector } : {}),
      ...(v.port !== undefined ? { port: v.port } : {}),
      ...(v.protocol ? { protocol: v.protocol } : {}),
      ...(v.parameter ? { parameter: v.parameter } : {}),
      ...(v.technicalImpact ? { technicalImpact: v.technicalImpact } : {}),
      ...(v.businessImpact ? { businessImpact: v.businessImpact } : {}),
      ...(v.remediation ? { remediation: v.remediation } : {}),
      // Prompt 12 passthrough (§59): code location, secret metadata
      // (fingerprints only — values were redacted at parse time),
      // dependency identity + review state.
      ...(f.filePath ? { filePath: f.filePath } : {}),
      ...(f.startLine !== undefined ? { startLine: f.startLine } : {}),
      ...(f.endLine !== undefined ? { endLine: f.endLine } : {}),
      ...(f.startColumn !== undefined ? { startColumn: f.startColumn } : {}),
      ...(f.endColumn !== undefined ? { endColumn: f.endColumn } : {}),
      ...(f.ruleId ? { ruleId: f.ruleId } : {}),
      ...(f.codeFlow ? { codeFlow: f.codeFlow } : {}),
      ...(f.secret ? { secret: f.secret } : {}),
      ...(f.componentName ? { componentName: f.componentName } : {}),
      ...(f.componentVersion ? { componentVersion: f.componentVersion } : {}),
      ...(f.componentPurl ? { componentPurl: f.componentPurl } : {}),
      ...(f.fixedVersion ? { fixedVersion: f.fixedVersion } : {}),
      ...(f.dependencyScope ? { dependencyScope: f.dependencyScope } : {}),
      ...(f.reachability ? { reachability: f.reachability } : {}),
      ...(f.reviewStatus ? { reviewStatus: f.reviewStatus } : {}),
      ...(f.generatedCode ? { generatedCode: true } : {}),
      ...(f.baselineStatus ? { baselineStatus: f.baselineStatus } : {}),
      // Prompt 13 passthrough (§51/§94): cloud-native identity fields.
      ...(f.origin ? { origin: f.origin } : {}),
      ...(f.imageDigest ? { imageDigest: f.imageDigest } : {}),
      ...(f.imageRef ? { imageRef: f.imageRef } : {}),
      ...(f.clusterRef ? { clusterRef: f.clusterRef } : {}),
      ...(f.namespace ? { namespace: f.namespace } : {}),
      ...(f.resourceKind ? { resourceKind: f.resourceKind } : {}),
      ...(f.resourceName ? { resourceName: f.resourceName } : {}),
      ...(f.containerName ? { containerName: f.containerName } : {}),
      ...(f.controlId ? { controlId: f.controlId } : {}),
      ...(f.packageType ? { packageType: f.packageType } : {}),
      ...(f.layerDigest ? { layerDigest: f.layerDigest } : {}),
      // Prompt 14 passthrough (§58/§61): cloud identity fields.
      ...(f.findingClass ? { findingClass: f.findingClass } : {}),
      ...(f.cloudProvider ? { cloudProvider: f.cloudProvider } : {}),
      ...(f.cloudAccountId ? { cloudAccountId: f.cloudAccountId } : {}),
      ...(f.providerResourceId ? { providerResourceId: f.providerResourceId } : {}),
      ...(f.cloudResourceType ? { cloudResourceType: f.cloudResourceType } : {}),
      ...(f.cloudRegion ? { cloudRegion: f.cloudRegion } : {}),
      ...(f.exposureClass ? { exposureClass: f.exposureClass } : {}),
      verificationStatus: "UNVERIFIED",
    };
  });

  // --- transactions (Prompt 8 §25/§30): canonicalized + scope-verdicted
  //     like endpoints. URLs persist with sensitive values redacted (§22
  //     rules apply to traffic too); display copies arrive already
  //     redacted from the parsers; raw bytes stay in the raw artifact,
  //     referenced per transaction (§26). ---
  const transactions: ProcessedTransaction[] = [];
  (result.transactions ?? []).forEach((tx, i) => {
    const canonical = canonicalizeUrl(tx.url);
    if (!canonical) return;
    const artifactRef = ctx.artifactKey ? `${ctx.artifactKey}#tx-${i}` : undefined;
    transactions.push({
      method: tx.method.toUpperCase(),
      url: redactUrl(canonical),
      host: tx.host,
      ...(tx.statusCode !== undefined ? { statusCode: tx.statusCode } : {}),
      source: tx.source,
      scopeStatus: matcher.isUrlAllowed(canonical) ? "IN_SCOPE" : "OUT_OF_SCOPE",
      apiKind: classifyApiKind(canonical),
      ...(tx.requestHash ? { requestHash: tx.requestHash } : {}),
      ...(tx.responseHash ? { responseHash: tx.responseHash } : {}),
      ...(tx.requestSize !== undefined ? { requestSize: tx.requestSize } : {}),
      ...(tx.responseSize !== undefined ? { responseSize: tx.responseSize } : {}),
      ...(tx.requestArtifactRef ?? artifactRef ? { requestArtifactRef: tx.requestArtifactRef ?? artifactRef } : {}),
      ...(tx.responseArtifactRef ?? artifactRef ? { responseArtifactRef: tx.responseArtifactRef ?? artifactRef } : {}),
      ...(tx.requestRedacted ? { requestRedacted: tx.requestRedacted } : {}),
      ...(tx.responseRedacted ? { responseRedacted: tx.responseRedacted } : {}),
      ...(tx.timestamp ? { observedAt: tx.timestamp } : {}),
    });
  });

  // --- websockets (Prompt 8 §49): inventory with scope verdicts ---
  const webSockets: ProcessedWebSocket[] = [];
  for (const ws of result.webSockets ?? []) {
    // canonicalizeUrl is http(s)-only by design; ws/wss URLs are
    // normalized here (lowercase host, default port stripped).
    let canonical = canonicalizeUrl(ws.url);
    if (!canonical) {
      try {
        const u = new URL(ws.url);
        if ((u.protocol === "ws:" || u.protocol === "wss:") && u.hostname && !u.username && !u.password) {
          const port = u.port && !((u.protocol === "wss:" && u.port === "443") || (u.protocol === "ws:" && u.port === "80")) ? `:${u.port}` : "";
          canonical = `${u.protocol}//${u.hostname.toLowerCase()}${port}${u.pathname || "/"}`;
        }
      } catch { /* not a URL — dropped */ }
    }
    if (!canonical) continue;
    webSockets.push({
      url: canonical,
      ...(ws.origin ? { origin: ws.origin } : {}),
      ...(ws.subprotocol ? { subprotocol: ws.subprotocol } : {}),
      source: ws.source,
      scopeStatus: matcher.isUrlAllowed(canonical) ? "IN_SCOPE" : "OUT_OF_SCOPE",
      ...(ws.authPresent !== undefined ? { authPresent: ws.authPresent } : {}),
    });
  }

  // --- API services (Prompt 9 §3/§5): canonical base URLs + scope
  //     verdicts; an out-of-scope API base is recorded, never promoted.
  const apiServiceByKey = new Map<string, ProcessedApiService>();
  for (const svc of result.apiServices ?? []) {
    const base = svc.baseUrl.replace(/\/+$/, "");
    if (!base || apiServiceByKey.has(base)) continue;
    let host = svc.host;
    try { host = new URL(base).hostname.toLowerCase(); } catch { /* keep parser-provided host */ }
    apiServiceByKey.set(base, {
      baseUrl: base, host,
      apiType: svc.apiType,
      ...(svc.version ? { version: svc.version } : {}),
      ...(svc.authenticationType ? { authenticationType: svc.authenticationType } : {}),
      ...(svc.specificationId ? { specificationId: svc.specificationId } : {}),
      source: svc.source,
      scopeStatus: matcher.isUrlAllowed(base) ? "IN_SCOPE" : "OUT_OF_SCOPE",
    });
  }
  const apiServices = [...apiServiceByKey.values()];

  // --- GraphQL services (Prompt 9 §26): inventory with scope verdicts.
  const graphqlByKey = new Map<string, ProcessedGraphqlService>();
  for (const g of result.graphqlServices ?? []) {
    if (!g.endpointUrl || graphqlByKey.has(g.endpointUrl)) continue;
    let host = g.host;
    try { host = new URL(g.endpointUrl).hostname.toLowerCase(); } catch { /* keep parser-provided host */ }
    graphqlByKey.set(g.endpointUrl, {
      endpointUrl: g.endpointUrl, host,
      schemaAvailable: g.schemaAvailable,
      queries: g.queries, mutations: g.mutations, subscriptions: g.subscriptions, types: g.types,
      ...(g.authenticationRequired !== undefined ? { authenticationRequired: g.authenticationRequired } : {}),
      source: g.source,
      scopeStatus: matcher.isUrlAllowed(g.endpointUrl) ? "IN_SCOPE" : "OUT_OF_SCOPE",
    });
  }
  const graphqlServices = [...graphqlByKey.values()];

  // --- JWT profiles (Prompt 9 §25): fingerprint-keyed passthrough. The
  //     records are metadata-only BY CONSTRUCTION (the inspector never
  //     emits the raw token), so nothing is redacted or dropped here.
  const jwtByFingerprint = new Map<string, ProcessedJwtProfile>();
  for (const p of result.jwtProfiles ?? []) {
    if (p.fingerprint && !jwtByFingerprint.has(p.fingerprint)) jwtByFingerprint.set(p.fingerprint, p);
  }
  const jwtProfiles = [...jwtByFingerprint.values()];

  // --- packet captures (Prompt 10 §43/§74): metadata only. A relative
  //     capture name (tcpdump's output file) is rebased onto THIS
  //     execution's raw artifact key; storage references (tshark inputs)
  //     pass through unchanged.
  const packetCaptures: ProcessedPacketCapture[] = (result.packetCaptures ?? []).map((c) => ({
    artifactRef: c.artifactRef.startsWith("scans/") || !ctx.artifactKey ? c.artifactRef : `${ctx.artifactKey}#${c.artifactRef}`,
    format: c.format,
    source: c.source,
    ...(c.sizeBytes !== undefined ? { sizeBytes: c.sizeBytes } : {}),
    ...(c.sha256 ? { sha256: c.sha256 } : {}),
    ...(c.durationSeconds !== undefined ? { durationSeconds: c.durationSeconds } : {}),
    ...(c.interfaceName ? { interfaceName: c.interfaceName } : {}),
  }));

  // --- components (Prompt 12 §45): PURL-keyed passthrough — inventory
  //     is data from manifests/scanners, deduped by the SDK parsers.
  const componentByPurl = new Map<string, ProcessedComponent>();
  for (const c of result.components ?? []) {
    if (c.purl && !componentByPurl.has(c.purl)) componentByPurl.set(c.purl, c);
  }
  const components = [...componentByPurl.values()];

  // --- cloud-native payload (Prompt 13): inventory + posture records
  //     pass through with identity intact; the stores persist them.
  const cloudNative: ProcessedResult["cloudNative"] = result.cloudNative ?? {
    images: [], workloads: [], controlAssessments: [], manifests: [], runtimeEvents: [],
  };

  // --- multi-cloud payload (Prompt 14 §14/§15): resources pass
  //     through with identity + scope verdict intact; out-of-scope
  //     resources are recorded with their verdict, never analyzed.
  const cloud: ProcessedResult["cloud"] = {
    resources: [
      ...(result.cloud?.resources ?? []).map((r) => ({ ...r, scopeStatus: "IN_SCOPE" as const })),
      ...(result.cloud?.outOfScopeResources ?? []).map((r) => ({ ...r, scopeStatus: "OUT_OF_SCOPE" as const })),
    ],
    identities: result.cloud?.identities ?? [],
    relationships: result.cloud?.relationships ?? [],
    controlAssessments: result.cloud?.controlAssessments ?? [],
    riskPaths: result.cloud?.riskPaths ?? [],
    ...(result.cloud?.snapshot ? { snapshot: result.cloud.snapshot } : {}),
  };

  return { assets, endpoints, services, technologies: [...techByKey.values()], findings, parameters, forms, transactions, webSockets, apiServices, graphqlServices, jwtProfiles, packetCaptures, components, cloudNative, cloud, suppressedEndpoints, isMock: result.mock };
}

/** Deterministic correlation grouping (Prompt 4 §36) — no AI, original
 *  evidence is preserved on each finding; groups share a correlation key. */
export function correlationKey(f: { fingerprint: string; host?: string; endpoint?: string; title: string }): string {
  return f.fingerprint;
}

export function groupFindings(findings: ProcessedFinding[]): Map<string, ProcessedFinding[]> {
  const groups = new Map<string, ProcessedFinding[]>();
  for (const f of findings) {
    const key = correlationKey(f);
    groups.set(key, [...(groups.get(key) ?? []), f]);
  }
  return groups;
}

/** Deterministic fixture risk scoring (Prompt 4 §37) — severity weights only,
 *  no fabricated external threat intelligence. */
const SEVERITY_WEIGHT: Record<string, number> = { CRITICAL: 40, HIGH: 25, MEDIUM: 12, LOW: 5, INFORMATIONAL: 1 };
export function fixtureRiskScore(findings: ProcessedFinding[]): number {
  const raw = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHT[f.severity] ?? 0) * f.confidence, 0);
  return Math.min(100, Math.round(raw));
}

/**
 * Prompt 7 correlation over processed findings (§18–§22, §34/§35): converts
 * persisted-shape findings to normalized vuln findings, runs the SDK
 * correlation engine, and maps the canonical results back — one canonical
 * finding per underlying issue, every source's evidence row preserved,
 * duplicates marked (never deleted), risk + confidence computed
 * deterministically with the same rules the SDK documents.
 */
/** Prompt 12: a processed finding is a SOURCE finding when it carries a
 *  code location, a component identity, or secret metadata. Source
 *  findings correlate with the line-stable source engine (§64–§68) —
 *  never with the host/endpoint vuln engine, whose canonical fingerprint
 *  would destroy source identity across snapshots. */
export function isSourceFinding(f: ProcessedFinding): boolean {
  return f.filePath !== undefined || f.componentPurl !== undefined || f.secret !== undefined;
}

/** Prompt 13: a processed finding is a CLOUD-NATIVE finding when it
 *  carries an origin (image / static-config / live-cluster / docker
 *  host). Cloud findings correlate in their own partition (§95): the
 *  §20/§54 fingerprints are the merge keys, and a static manifest
 *  observation + a live cluster observation of the same configuration
 *  issue merge into ONE canonical finding that preserves BOTH
 *  observations (§51/§103) — never into the source partition, whose
 *  snapshot identity semantics would be wrong for images/clusters. */
export function isCloudNativeFinding(f: ProcessedFinding): boolean {
  return f.origin !== undefined;
}

/** Prompt 14 §62: an IaC (Checkov) observation and a LIVE cloud
 *  observation describe the same issue when the governed rule mapping
 *  connects them AND the resource identity matches reliably (the IaC
 *  resource name equals the deployed resource name). Unmapped rules
 *  and unmatched names never merge — correlation stays conservative. */
export function sameIacLiveIdentity(a: ProcessedFinding, b: ProcessedFinding): boolean {
  const iac = a.origin === "STATIC_CONFIGURATION_FINDING" ? a : b.origin === "STATIC_CONFIGURATION_FINDING" ? b : null;
  const live = iac === a ? b : a;
  if (!iac || live.origin !== "CLOUD_FINDING") return false;
  const iacKey = iacLiveMatchKey({ ruleId: iac.ruleId, resourceName: iac.resourceName });
  const liveKey = liveMatchKey({ ruleId: live.ruleId, resourceName: live.resourceName });
  return iacKey !== null && iacKey === liveKey;
}

function correlateCloudProcessed(
  findings: ProcessedFinding[],
): { findings: ProcessedFinding[]; stats: CorrelationStats } {
  // Group by fingerprint first (exact identity, §20/§54)…
  const groups = new Map<string, ProcessedFinding[]>();
  for (const f of findings) groups.set(f.fingerprint, [...(groups.get(f.fingerprint) ?? []), f]);
  // …then merge groups sharing a configuration identity across origins
  // (static manifest ↔ live cluster, §51/§103).
  const groupList = [...groups.values()];
  const merged: ProcessedFinding[][] = [];
  const consumed = new Set<number>();
  for (let i = 0; i < groupList.length; i++) {
    if (consumed.has(i)) continue;
    const group = [...groupList[i]!];
    for (let j = i + 1; j < groupList.length; j++) {
      if (consumed.has(j)) continue;
      const a = group[0]!;
      const b = groupList[j]![0]!;
      if (a.origin !== b.origin && (sameConfigurationIdentity(a, b) || sameIacLiveIdentity(a, b))) {
        group.push(...groupList[j]!);
        consumed.add(j);
      }
    }
    merged.push(group);
  }
  const out: ProcessedFinding[] = merged.map((members) => {
    const primary = members[0]!;
    const sources = [...new Set(members.flatMap((m) => m.sources))];
    const risk = computeRisk({
      severity: primary.severity as NormalizedFinding["severity"],
      ...(primary.cvssScore !== undefined ? { cvssScore: primary.cvssScore } : {}),
      confidence: primary.confidence,
      verificationStatus: "UNVERIFIED",
    });
    const origins = [...new Set(members.map((m) => m.origin).filter(Boolean))];
    return {
      ...primary,
      sources,
      evidenceRows: members.flatMap((m) => m.evidenceRows),
      evidenceSummary: members.map((m) => m.evidenceSummary).filter(Boolean).join("\n"),
      riskScore: risk.score,
      riskBand: risk.band,
      riskExplanation: [
        ...risk.explanation,
        ...(origins.length > 1 ? [`CORRELATED_OBSERVATIONS: ${origins.join(" + ")} — static and live evidence preserved (§103)`] : []),
        ...(sources.length > 1 ? [`CORROBORATED_BY: ${sources.join(", ")}`] : []),
      ],
      confidenceBand: primary.confidence >= 0.8 ? "HIGH" : primary.confidence >= 0.5 ? "MEDIUM" : "LOW",
      verificationStatus: "UNVERIFIED",
    };
  });
  const byTool: CorrelationStats["byTool"] = {};
  for (const f of findings) {
    const entry = byTool[f.sourceTool] ?? { total: 0, unique: 0, corroborated: 0 };
    entry.total += 1;
    byTool[f.sourceTool] = entry;
  }
  for (const o of out) {
    const entry = byTool[o.sourceTool] ?? { total: 0, unique: 0, corroborated: 0 };
    entry.unique += 1;
    if (o.sources.length > 1) entry.corroborated += 1;
    byTool[o.sourceTool] = entry;
  }
  return {
    findings: out,
    stats: {
      total: findings.length,
      unique: out.length,
      duplicatesMerged: findings.length - out.length,
      corroborated: out.filter((f) => f.sources.length > 1).length,
      byTool,
    },
  };
}

export function correlateProcessedFindings(
  findings: ProcessedFinding[],
  opts: { assetCriticality?: string; maxFindings?: number } = {},
): { findings: ProcessedFinding[]; stats: CorrelationStats } {
  const cloudFindings = findings.filter(isCloudNativeFinding);
  const rest = findings.filter((f) => !isCloudNativeFinding(f));
  const mergeStats = (parts: { findings: ProcessedFinding[]; stats: CorrelationStats }[]) => {
    const byTool: CorrelationStats["byTool"] = {};
    for (const part of parts) {
      for (const [tool, v] of Object.entries(part.stats.byTool)) {
        const existing = byTool[tool] ?? { total: 0, unique: 0, corroborated: 0 };
        byTool[tool] = { total: existing.total + v.total, unique: existing.unique + v.unique, corroborated: existing.corroborated + v.corroborated };
      }
    }
    return {
      findings: parts.flatMap((p) => p.findings),
      stats: {
        total: parts.reduce((s, p) => s + p.stats.total, 0),
        unique: parts.reduce((s, p) => s + p.stats.unique, 0),
        duplicatesMerged: parts.reduce((s, p) => s + p.stats.duplicatesMerged, 0),
        corroborated: parts.reduce((s, p) => s + p.stats.corroborated, 0),
        byTool,
      },
    };
  };
  const parts: { findings: ProcessedFinding[]; stats: CorrelationStats }[] = [];
  if (cloudFindings.length > 0) parts.push(correlateCloudProcessed(cloudFindings));
  const sourceFindings = rest.filter(isSourceFinding);
  const otherFindings = rest.filter((f) => !isSourceFinding(f));
  if (otherFindings.length > 0) parts.push(correlateVulnProcessed(otherFindings, opts));
  if (sourceFindings.length > 0) parts.push(correlateSourceProcessed(sourceFindings));
  if (parts.length === 0) return correlateVulnProcessed(findings, opts);
  return mergeStats(parts);
}

/** Source correlation (§64–§68 + §70): fingerprint merges + conservative
 *  cross-tool SAST merges via the SDK engine; risk from the shared
 *  deterministic engine plus source-specific factor explanations. */
function correlateSourceProcessed(
  findings: ProcessedFinding[],
): { findings: ProcessedFinding[]; stats: CorrelationStats } {
  const projections: NormalizedFinding[] = findings.map((f) => ({
    title: f.title, description: f.description,
    severity: f.severity as NormalizedFinding["severity"],
    confidence: f.confidence,
    ...(f.host ? { host: f.host } : {}),
    ...(f.endpoint ? { endpoint: f.endpoint } : {}),
    ...(f.cve ? { cve: f.cve } : {}),
    ...(f.cwe ? { cwe: f.cwe } : {}),
    ...(f.cvssScore !== undefined ? { cvssScore: f.cvssScore } : {}),
    ...(f.cvssVector ? { cvssVector: f.cvssVector } : {}),
    ...(f.owaspCategory ? { owaspCategory: f.owaspCategory } : {}),
    evidence: f.evidenceSummary,
    ...(f.remediation ? { remediation: f.remediation } : {}),
    references: f.references.map((r) => r.url),
    sourceTool: f.sourceTool,
    sourceFingerprint: f.fingerprint,
    ...(f.filePath ? { filePath: f.filePath } : {}),
    ...(f.startLine !== undefined ? { startLine: f.startLine } : {}),
    ...(f.endLine !== undefined ? { endLine: f.endLine } : {}),
    ...(f.startColumn !== undefined ? { startColumn: f.startColumn } : {}),
    ...(f.endColumn !== undefined ? { endColumn: f.endColumn } : {}),
    ...(f.ruleId ? { ruleId: f.ruleId } : {}),
    ...(f.codeFlow ? { codeFlow: f.codeFlow } : {}),
    ...(f.secret ? { secret: f.secret } : {}),
    ...(f.componentName ? { componentName: f.componentName } : {}),
    ...(f.componentVersion ? { componentVersion: f.componentVersion } : {}),
    ...(f.componentPurl ? { componentPurl: f.componentPurl } : {}),
    ...(f.fixedVersion ? { fixedVersion: f.fixedVersion } : {}),
    ...(f.dependencyScope ? { dependencyScope: f.dependencyScope as NormalizedFinding["dependencyScope"] } : {}),
    ...(f.reachability ? { reachability: f.reachability as NormalizedFinding["reachability"] } : {}),
    ...(f.reviewStatus ? { reviewStatus: f.reviewStatus as NormalizedFinding["reviewStatus"] } : {}),
    ...(f.generatedCode ? { generatedCode: true } : {}),
    ...(f.baselineStatus ? { baselineStatus: f.baselineStatus as NormalizedFinding["baselineStatus"] } : {}),
  }));
  const { findings: correlated, stats: sourceStats } = correlateSourceFindings(projections);
  const byFingerprint = new Map(findings.map((f) => [f.fingerprint, f]));
  const out: ProcessedFinding[] = correlated.map((c) => {
    const members = c.memberFingerprints
      .map((fp) => byFingerprint.get(fp))
      .filter((m): m is ProcessedFinding => m !== undefined);
    const primary = members[0] ?? byFingerprint.get(c.sourceFingerprint) ?? findings[0]!;
    const risk = computeRisk({
      severity: c.severity,
      ...(c.cvssScore !== undefined ? { cvssScore: c.cvssScore } : {}),
      confidence: c.confidence,
      verificationStatus: "UNVERIFIED",
    });
    return {
      ...primary,
      title: c.title,
      description: c.description,
      severity: c.severity,
      confidence: c.confidence,
      fingerprint: c.sourceFingerprint,
      sources: c.sources,
      sourceTool: primary.sourceTool,
      evidenceRows: members.flatMap((m) => m.evidenceRows),
      references: c.references.map((url) => ({ type: "OTHER", label: url, url })),
      ...(c.cve ? { cve: c.cve } : {}),
      ...(c.cwe ? { cwe: c.cwe } : {}),
      ...(c.cvssScore !== undefined ? { cvssScore: c.cvssScore } : {}),
      ...(c.fixedVersion ? { fixedVersion: c.fixedVersion } : {}),
      ...(c.codeFlow ? { codeFlow: c.codeFlow } : {}),
      riskScore: risk.score,
      riskBand: risk.band,
      riskExplanation: [...risk.explanation, ...sourceRiskFactors(c).map((x) => `${x.factor}: ${x.detail}`)],
      confidenceBand: c.confidence >= 0.8 ? "HIGH" : c.confidence >= 0.5 ? "MEDIUM" : "LOW",
      verificationStatus: "UNVERIFIED",
    };
  });
  const byTool: CorrelationStats["byTool"] = {};
  for (const f of findings) {
    const entry = byTool[f.sourceTool] ?? { total: 0, unique: 0, corroborated: 0 };
    entry.total += 1;
    byTool[f.sourceTool] = entry;
  }
  for (const c of correlated) {
    const primary = byFingerprint.get(c.memberFingerprints[0] ?? c.sourceFingerprint);
    if (primary) {
      byTool[primary.sourceTool]!.unique += 1;
      if (c.sources.length > 1) byTool[primary.sourceTool]!.corroborated += 1;
    }
  }
  return {
    findings: out,
    stats: {
      total: sourceStats.input,
      unique: sourceStats.canonical,
      duplicatesMerged: sourceStats.duplicatesMerged,
      corroborated: correlated.filter((c) => c.sources.length > 1).length,
      byTool,
    },
  };
}

function correlateVulnProcessed(
  findings: ProcessedFinding[],
  opts: { assetCriticality?: string; maxFindings?: number } = {},
): { findings: ProcessedFinding[]; stats: CorrelationStats } {
  const normalized: NormalizedVulnFinding[] = findings.map((f) => ({
    title: f.title, description: f.description,
    severity: f.severity as NormalizedVulnFinding["severity"],
    confidence: f.confidence,
    ...(f.host ? { host: f.host } : {}),
    ...(f.endpoint ? { endpoint: f.endpoint } : {}),
    ...(f.parameter ? { parameter: f.parameter } : {}),
    ...(f.port !== undefined ? { port: f.port } : {}),
    ...(f.protocol ? { protocol: f.protocol } : {}),
    ...(f.cve ? { cve: f.cve } : {}),
    ...(f.cwe ? { cwe: f.cwe } : {}),
    ...(f.cvssScore !== undefined ? { cvssScore: f.cvssScore } : {}),
    ...(f.cvssVector ? { cvssVector: f.cvssVector } : {}),
    ...(f.owaspCategory ? { owaspCategory: f.owaspCategory } : {}),
    ...(f.technicalImpact ? { technicalImpact: f.technicalImpact } : {}),
    ...(f.businessImpact ? { businessImpact: f.businessImpact } : {}),
    evidence: f.evidenceSummary,
    remediation: f.remediation ?? "",
    references: f.references.map((r) => r.url),
    referencesDetailed: f.references.map((r) => ({ ...r, type: r.type as NormalizedVulnFinding["referencesDetailed"][number]["type"] })),
    sourceTool: f.sourceTool,
    sourceFingerprint: f.fingerprint,
    vulnClass: f.vulnClass ?? "GENERIC_VULNERABILITY",
    sourceConfidence: f.confidence,
    assetCriticality: (opts.assetCriticality as NormalizedVulnFinding["assetCriticality"]) ?? "UNSPECIFIED",
    verificationStatus: "UNVERIFIED",
  }));
  const { findings: correlated, stats } = sdkCorrelateFindings(normalized, opts);
  const byFingerprint = new Map(findings.map((f) => [f.fingerprint, f]));
  const out: ProcessedFinding[] = correlated.map((c) => {
    const primary = byFingerprint.get(c.finding.sourceFingerprint) ?? findings[0]!;
    const members = c.sources
      .map((s) => byFingerprint.get(s.sourceFingerprint))
      .filter((m): m is ProcessedFinding => m !== undefined);
    return {
      ...primary,
      title: c.finding.title,
      description: c.finding.description,
      severity: c.finding.severity,
      confidence: c.confidenceScore,
      confidenceBand: c.confidenceBand,
      verificationStatus: c.verificationStatus,
      riskScore: c.riskScore,
      riskBand: c.riskBand,
      riskExplanation: c.riskExplanation,
      fingerprint: c.canonicalFingerprint,
      sources: c.sources.map((s) => s.tool),
      sourceTool: primary.sourceTool,
      evidenceRows: members.flatMap((m) => m.evidenceRows),
      references: c.finding.referencesDetailed.map((r) => ({ type: r.type, label: r.label, url: r.url })),
      ...(c.finding.cve ? { cve: c.finding.cve } : {}),
      ...(c.finding.cwe ? { cwe: c.finding.cwe } : {}),
      ...(c.finding.cvssScore !== undefined ? { cvssScore: c.finding.cvssScore } : {}),
      ...(c.finding.remediation ? { remediation: c.finding.remediation } : {}),
      ...(members.map((m) => m.firstSeenAt).filter(Boolean).sort()[0] ? { firstSeenAt: members.map((m) => m.firstSeenAt).filter(Boolean).sort()[0] } : {}),
      ...(members.map((m) => m.lastSeenAt).filter(Boolean).sort().at(-1) ? { lastSeenAt: members.map((m) => m.lastSeenAt).filter(Boolean).sort().at(-1) } : {}),
    };
  });
  return { findings: out, stats };
}

/** Scan findings summary (§45) + tool contribution (§46), computed from
 *  real processed findings only — the GUI renders exactly these numbers. */
export function scanFindingsSummary(
  canonical: ProcessedFinding[],
  stats: { totalInputs: number; duplicatesMerged: number; byTool: Record<string, { total: number; unique: number; corroborated: number }> },
): Record<string, unknown> {
  const bySeverity: Record<string, number> = {};
  for (const f of canonical) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  return {
    totalFindings: stats.totalInputs,
    uniqueFindings: canonical.length,
    duplicatesMerged: stats.duplicatesMerged,
    bySeverity,
    confirmed: canonical.filter((f) => f.verificationStatus === "CONFIRMED").length,
    likely: canonical.filter((f) => f.verificationStatus === "LIKELY").length,
    unverified: canonical.filter((f) => (f.verificationStatus ?? "UNVERIFIED") === "UNVERIFIED").length,
    falsePositives: 0,
    acceptedRisks: 0,
    byTool: stats.byTool,
  };
}
