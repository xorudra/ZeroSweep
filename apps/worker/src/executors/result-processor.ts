import {
  canonicalizeHostname, canonicalizeUrl, classifyEndpointType, detectCrawlerTrap, detectWildcardGroups,
  endpointIdentityKey, extractParameterNames, findingFingerprint, redactUrl, sensitiveRouteLabel,
  ScopeMatcher, type DnsRecordSet, type NormalizedSecurityResult,
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
}

export interface ProcessedTechnology {
  host?: string;
  name: string;
  version?: string;
  category?: string;
  source?: string;
  confidence?: number;
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
}

export interface ProcessedResult {
  assets: ProcessedAsset[];
  endpoints: ProcessedEndpoint[];
  services: ProcessedService[];
  technologies: ProcessedTechnology[];
  findings: ProcessedFinding[];
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
  ctx: { scopeRules: ScopeRules; toolExecutionId: string; toolSlug?: string },
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
    if (serviceKeys.has(key)) continue;
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

  const findings: ProcessedFinding[] = result.findings.map((f) => ({
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
  }));
  return { assets, endpoints, services, technologies: [...techByKey.values()], findings, parameters, forms, suppressedEndpoints, isMock: result.mock };
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
