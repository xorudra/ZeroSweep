import {
  canonicalizeHostname, canonicalizeUrl, extractParameterNames, findingFingerprint, redactUrl,
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
  //     values of sensitive parameters redacted before storage (§22) ---
  const endpointByKey = new Map<string, ProcessedEndpoint>();
  const addEndpoint = (url: string, method: string, statusCode: number | undefined, parameterNames: string[] | undefined, source: string | undefined): void => {
    const canonical = canonicalizeUrl(url);
    if (!canonical) return;
    const parsed = new URL(canonical);
    const key = `${method.toUpperCase()}|${parsed.origin}${parsed.pathname}`;
    const existing = endpointByKey.get(key);
    if (existing) {
      existing.parameterNames = [...new Set([...existing.parameterNames, ...(parameterNames ?? extractParameterNames(canonical))])].sort();
      return;
    }
    endpointByKey.set(key, {
      url: redactUrl(canonical),
      method: method.toUpperCase(),
      ...(statusCode !== undefined ? { statusCode } : {}),
      parameterNames: parameterNames ?? extractParameterNames(canonical),
      ...(source ? { source } : {}),
      scopeStatus: matcher.isUrlAllowed(canonical) ? "IN_SCOPE" : "OUT_OF_SCOPE",
    });
  };
  for (const ep of result.endpoints) addEndpoint(ep.url, ep.method ?? "GET", ep.statusCode, ep.parameterNames, ep.source ?? tool);
  // §30: out-of-scope redirect targets become endpoint REFERENCES only.
  for (const svc of result.services) {
    if (!svc.redirectLocation) continue;
    const target = canonicalizeUrl(svc.redirectLocation);
    const fromHost = canonicalizeHostname(svc.host) ?? canonicalHost(svc.host);
    if (target && new URL(target).hostname !== fromHost) addEndpoint(target, "GET", undefined, undefined, tool);
  }
  const endpoints = [...endpointByKey.values()];

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
  return { assets, endpoints, services, technologies: [...techByKey.values()], findings, isMock: result.mock };
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
