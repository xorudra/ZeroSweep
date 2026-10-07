import type {
  NormalizedAsset, NormalizedEndpoint, NormalizedSecurityResult, NormalizedService, NormalizedTechnology,
} from "../findings/finding.types";
import { ScopeMatcher } from "../scope/scope.matcher";
import { canonicalizeHostname, canonicalizeUrl, endpointIdentityKey, extractParameterNames, redactUrl } from "./normalize";
import type { BudgetTracker } from "./budget";

/**
 * ReconResultAggregator (Prompt 5 §17–§18, §23, §30): merges every recon
 * adapter's normalized output into ONE inventory. Canonicalization happens
 * before comparison, duplicates collapse, provenance (which tools reported
 * an entity) is preserved as a source list, and EVERY discovered entity gets
 * a scope verdict here — in-scope, or recorded OUT_OF_SCOPE and never
 * promoted into a scan target.
 */
export interface AggregatorInput {
  tool: string;
  result: NormalizedSecurityResult;
}

interface AssetAcc extends NormalizedAsset { sourceSet: Set<string> }

export class ReconResultAggregator {
  constructor(
    private readonly scope: ScopeMatcher,
    private readonly budget?: BudgetTracker,
  ) {}

  aggregate(inputs: AggregatorInput[]): NormalizedSecurityResult {
    const metrics: Record<string, number> = {};
    const assets = new Map<string, AssetAcc>();
    const services = new Map<string, NormalizedService>();
    const endpoints = new Map<string, NormalizedEndpoint>();
    const technologies = new Map<string, NormalizedTechnology>();
    let duplicatesRemoved = 0;

    const addEndpoint = (ep: NormalizedEndpoint, tool: string): void => {
      const canonical = canonicalizeUrl(ep.url);
      if (!canonical) { metrics.invalidEndpoints = (metrics.invalidEndpoints ?? 0) + 1; return; }
      // Endpoint identity (§20/§33): method + origin + path. Query VALUES are
      // ephemeral (never merged on), parameter NAMES are an attribute that
      // unions across observations — /p?id=1 and /p?lang=en are one endpoint.
      const key = endpointIdentityKey(ep.method ?? "GET", canonical);
      const existing = endpoints.get(key);
      if (existing) {
        duplicatesRemoved++;
        existing.parameterNames = [...new Set([...(existing.parameterNames ?? []), ...(ep.parameterNames ?? extractParameterNames(canonical))])].sort();
        // Provenance (Prompt 6 §26): one canonical endpoint, many sources.
        existing.sources = [...new Set([...(existing.sources ?? [existing.source ?? tool]), tool, ...(ep.sources ?? [ep.source ?? tool])])].sort();
        if (existing.statusCode === undefined && ep.statusCode !== undefined) existing.statusCode = ep.statusCode;
        if (!existing.contentType && ep.contentType) existing.contentType = ep.contentType;
        if (existing.contentLength === undefined && ep.contentLength !== undefined) existing.contentLength = ep.contentLength;
        if (!existing.redirectLocation && ep.redirectLocation) existing.redirectLocation = ep.redirectLocation;
        return;
      }
      // Historical (archive) and crawl inventories are budget-capped (§28).
      if (this.budget) {
        const kind = tool === "gau" || tool === "waybackurls" ? "historicalUrls" : tool === "katana" ? "crawlUrls" : null;
        if (kind && !this.budget.tryConsume(kind)) { metrics.budgetTruncatedEndpoints = (metrics.budgetTruncatedEndpoints ?? 0) + 1; return; }
      }
      endpoints.set(key, {
        url: redactUrl(canonical),
        method: ep.method ?? "GET",
        ...(ep.statusCode !== undefined ? { statusCode: ep.statusCode } : {}),
        ...(ep.contentLength !== undefined ? { contentLength: ep.contentLength } : {}),
        ...(ep.contentType ? { contentType: ep.contentType } : {}),
        ...(ep.redirectLocation ? { redirectLocation: ep.redirectLocation } : {}),
        ...(ep.fingerprint ? { fingerprint: ep.fingerprint } : {}),
        parameterNames: ep.parameterNames ?? extractParameterNames(canonical),
        source: ep.source ?? tool,
        sources: [...new Set([tool, ...(ep.sources ?? [ep.source ?? tool])])].sort(),
        scopeStatus: this.scope.isUrlAllowed(canonical) ? "IN_SCOPE" : "OUT_OF_SCOPE",
      });
    };

    for (const { tool, result } of inputs) {
      for (const [k, v] of Object.entries(result.metrics)) metrics[`${tool}.${k}`] = v;
      metrics.findingsDropped = (metrics.findingsDropped ?? 0) + result.findings.length; // §47: recon strips findings defensively

      for (const asset of result.assets) {
        const host = canonicalizeHostname(asset.host);
        if (!host) { metrics.invalidAssets = (metrics.invalidAssets ?? 0) + 1; continue; }
        const existing = assets.get(host);
        if (existing) {
          duplicatesRemoved++;
          existing.sourceSet.add(tool);
          for (const s of asset.sources ?? []) existing.sourceSet.add(s);
          if (!existing.ip && asset.ip) existing.ip = asset.ip;
          if (asset.wildcardSuspect) existing.wildcardSuspect = true;
          existing.dnsRecords = mergeDns(existing.dnsRecords, asset.dnsRecords);
          continue;
        }
        if (this.budget && !this.budget.tryConsume("subdomains")) {
          metrics.budgetTruncatedAssets = (metrics.budgetTruncatedAssets ?? 0) + 1;
          continue;
        }
        const acc: AssetAcc = {
          host,
          type: asset.type,
          ...(asset.ip ? { ip: asset.ip } : {}),
          ...(asset.dnsRecords ? { dnsRecords: asset.dnsRecords } : {}),
          ...(asset.wildcardSuspect ? { wildcardSuspect: true } : {}),
          sourceSet: new Set([tool, ...(asset.sources ?? [])]),
        };
        assets.set(host, acc);
      }

      for (const svc of result.services) {
        const host = canonicalizeHostname(svc.host);
        if (!host) continue;
        const key = `${host}|${svc.port}|${svc.protocol}`;
        if (services.has(key)) { duplicatesRemoved++; continue; }
        services.set(key, { ...svc, host });
        // §30: a redirect out of scope is stored as a reference endpoint —
        // the third-party destination never becomes an asset or a service.
        if (svc.redirectLocation) {
          const target = canonicalizeUrl(svc.redirectLocation);
          if (target && new URL(target).hostname !== host) {
            addEndpoint({ url: target, method: "GET", source: tool }, tool);
          }
        }
      }

      for (const ep of result.endpoints) addEndpoint(ep, tool);

      for (const tech of result.technologies) {
        const host = tech.host ? canonicalizeHostname(tech.host) ?? undefined : undefined;
        const key = `${host ?? ""}|${tech.name.toLowerCase()}`;
        const existing = technologies.get(key);
        if (existing) {
          duplicatesRemoved++;
          if (!existing.version && tech.version) existing.version = tech.version;
          if ((tech.confidence ?? 0) > (existing.confidence ?? 0)) existing.confidence = tech.confidence;
          continue;
        }
        technologies.set(key, { ...tech, ...(host ? { host } : {}) });
      }
    }

    // Parameters + forms merge (Prompt 6 §27/§30/§33): one parameter per
    // endpoint+name+location with unioned provenance; forms deduped per
    // endpoint+method with unioned field names.
    const parameterMap = new Map<string, import("../findings/finding.types").NormalizedEndpointParameter & { sourceSet: Set<string> }>();
    const formMap = new Map<string, import("../findings/finding.types").NormalizedForm>();
    for (const { tool, result } of inputs) {
      for (const param of result.parameters ?? []) {
        const canonical = canonicalizeUrl(param.endpointUrl);
        if (!canonical) continue;
        const base = canonical.split("?")[0]!;
        const key = `${base}|${param.name}|${param.location}`;
        const existingParam = parameterMap.get(key);
        if (existingParam) { duplicatesRemoved++; for (const s of param.sources ?? [tool]) existingParam.sourceSet.add(s); continue; }
        parameterMap.set(key, { ...param, endpointUrl: base, sourceSet: new Set(param.sources ?? [tool]) });
      }
      for (const form of result.forms ?? []) {
        const canonical = canonicalizeUrl(form.endpointUrl);
        if (!canonical) continue;
        const key = `${canonical}|${form.method.toUpperCase()}`;
        const existingForm = formMap.get(key);
        if (existingForm) { existingForm.fieldNames = [...new Set([...existingForm.fieldNames, ...form.fieldNames])].sort(); continue; }
        formMap.set(key, { ...form, endpointUrl: redactUrl(canonical), fieldNames: [...new Set(form.fieldNames)].sort() });
      }
    }

    const assetList: NormalizedAsset[] = [...assets.values()].map((acc) => {
      const { sourceSet, ...rest } = acc;
      const verdict = this.scope.isDiscoveredAssetInScope(acc.host);
      return { ...rest, sources: [...sourceSet].sort(), scopeStatus: verdict.allowed ? "IN_SCOPE" : "OUT_OF_SCOPE" };
    });
    metrics.duplicatesRemoved = duplicatesRemoved;
    metrics.assetsInScope = assetList.filter((a) => a.scopeStatus === "IN_SCOPE").length;
    metrics.assetsOutOfScope = assetList.filter((a) => a.scopeStatus === "OUT_OF_SCOPE").length;
    if (assetList.some((a) => a.wildcardSuspect)) metrics.wildcardDetected = 1;

    return {
      assets: assetList,
      services: [...services.values()],
      endpoints: [...endpoints.values()],
      technologies: [...technologies.values()],
      parameters: [...parameterMap.values()].map((p) => {
        const { sourceSet, ...rest } = p;
        return { ...rest, sources: [...sourceSet].sort() };
      }),
      forms: [...formMap.values()],
      findings: [],
      artifacts: [],
      metrics,
      mock: inputs.every((i) => i.result.mock) && inputs.length > 0,
    };
  }
}

function mergeDns(
  a: NormalizedAsset["dnsRecords"],
  b: NormalizedAsset["dnsRecords"],
): NormalizedAsset["dnsRecords"] {
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
