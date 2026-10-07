import type {
  NormalizedEndpoint, NormalizedEndpointParameter, NormalizedForm, NormalizedSecurityResult,
} from "../findings/finding.types";
import { ScopeMatcher } from "../scope/scope.matcher";
import { canonicalizeUrl, endpointIdentityKey, extractParameterNames, redactUrl } from "../recon/normalize";
import type { BudgetTracker } from "../recon/budget";
import {
  classifyEndpointType, detectCrawlerTrap, isJavaScriptResource, sensitiveRouteLabel,
} from "./classify";
import { Soft404Detector, detectWildcardGroups } from "./soft404";

/**
 * WebSurfaceAggregator (Prompt 6 §39): merges crawler + historical +
 * content-discovery + parameter-discovery results into ONE canonical web
 * surface. Responsibilities, in order: canonicalize → classify →
 * soft-404 filter → wildcard collapse → trap filter → deduplicate
 * (provenance preserved as source lists) → scope-validate EVERY route.
 * Out-of-scope routes are recorded with their verdict and never flow
 * downstream (§40); parameters attach only to in-scope endpoints (§28).
 */
export interface WebSurfaceInput {
  tool: string;
  result: NormalizedSecurityResult;
}

interface EndpointAcc extends NormalizedEndpoint { sourceSet: Set<string> }

export class WebSurfaceAggregator {
  constructor(
    private readonly scope: ScopeMatcher,
    private readonly options: { soft404?: Soft404Detector; budget?: BudgetTracker } = {},
  ) {}

  aggregate(inputs: WebSurfaceInput[]): NormalizedSecurityResult {
    const metrics: Record<string, number> = {};
    const endpoints = new Map<string, EndpointAcc>();
    const parameters = new Map<string, NormalizedEndpointParameter & { sourceSet: Set<string> }>();
    const forms = new Map<string, NormalizedForm>();
    let duplicatesRemoved = 0;

    const rawEndpoints: Array<{ ep: NormalizedEndpoint; tool: string }> = [];
    for (const { tool, result } of inputs) {
      for (const [k, v] of Object.entries(result.metrics)) metrics[`${tool}.${k}`] = v;
      metrics.findingsDropped = (metrics.findingsDropped ?? 0) + (result.findings ?? []).length; // discovery never carries findings
      for (const ep of result.endpoints) rawEndpoints.push({ ep, tool });
      for (const form of result.forms ?? []) {
        const canonical = canonicalizeUrl(form.endpointUrl);
        if (!canonical) continue;
        const key = `${canonical}|${form.method.toUpperCase()}`;
        const existing = forms.get(key);
        if (existing) {
          existing.fieldNames = [...new Set([...existing.fieldNames, ...form.fieldNames])].sort();
        } else {
          forms.set(key, { endpointUrl: redactUrl(canonical), method: form.method.toUpperCase(), fieldNames: [...new Set(form.fieldNames)].sort(), ...(form.encodingType ? { encodingType: form.encodingType } : {}), ...(form.source ? { source: form.source } : {}) });
        }
      }
      for (const param of result.parameters ?? []) {
        const canonical = canonicalizeUrl(param.endpointUrl);
        if (!canonical) continue;
        const base = canonical.split("?")[0]!;
        const key = `${base}|${param.name}|${param.location}`;
        const existing = parameters.get(key);
        if (existing) {
          duplicatesRemoved++;
          for (const s of param.sources ?? []) existing.sourceSet.add(s);
          existing.confidence = Math.max(existing.confidence ?? 0, param.confidence ?? 0);
          continue;
        }
        parameters.set(key, { ...param, endpointUrl: base, sourceSet: new Set(param.sources ?? []) });
      }
    }

    // Soft-404 filtering (§17): calibrated baselines identify responses the
    // application fabricates for nonexistent paths.
    let survivors = rawEndpoints;
    const detector = this.options.soft404;
    if (detector?.calibrated) {
      survivors = survivors.filter(({ ep }) => {
        if (ep.statusCode !== 404 && detector.matchesBaseline(ep.fingerprint)) {
          metrics.soft404Filtered = (metrics.soft404Filtered ?? 0) + 1;
          return false;
        }
        return true;
      });
    }

    // Wildcard collapse (§19): identical success fingerprints across many
    // distinct paths = one wildcard behaviour, not an inventory of fakes.
    const fingerprinted = survivors.map((s) => s.ep);
    const { kept, groups } = detectWildcardGroups(fingerprinted);
    const keptSet = new Set(kept.map((e) => e.url));
    const wildcardUrls = new Set(groups.map((g) => g.representative.url));
    if (groups.length > 0) {
      metrics.wildcardRoutes = (metrics.wildcardRoutes ?? 0) + groups.length;
      metrics.wildcardCollapsed = (metrics.wildcardCollapsed ?? 0) + groups.reduce((n, g) => n + g.collapsed.length, 0);
      survivors = survivors.filter((s) => keptSet.has(s.ep.url));
    }

    for (const { ep, tool } of survivors) {
      const canonical = canonicalizeUrl(ep.url);
      if (!canonical) { metrics.invalidEndpoints = (metrics.invalidEndpoints ?? 0) + 1; continue; }
      // Crawler-trap guard (§46/§47): trap-shaped URLs are not inventory.
      if (detectCrawlerTrap(canonical).trap) { metrics.trapFiltered = (metrics.trapFiltered ?? 0) + 1; continue; }
      const key = endpointIdentityKey(ep.method ?? "GET", canonical);
      const existing = endpoints.get(key);
      if (existing) {
        duplicatesRemoved++;
        existing.sourceSet.add(tool);
        for (const s of ep.sources ?? []) existing.sourceSet.add(s);
        existing.parameterNames = [...new Set([...(existing.parameterNames ?? []), ...(ep.parameterNames ?? extractParameterNames(canonical))])].sort();
        if (existing.statusCode === undefined && ep.statusCode !== undefined) existing.statusCode = ep.statusCode;
        if (!existing.contentType && ep.contentType) existing.contentType = ep.contentType;
        if (existing.contentLength === undefined && ep.contentLength !== undefined) existing.contentLength = ep.contentLength;
        if (!existing.redirectLocation && ep.redirectLocation) existing.redirectLocation = ep.redirectLocation;
        if (!existing.fingerprint && ep.fingerprint) existing.fingerprint = ep.fingerprint;
        continue;
      }
      if (this.options.budget) {
        const kind = classifyEndpointType(canonical) === "FILE" ? "files" : classifyEndpointType(canonical) === "DIRECTORY" ? "directories" : "contentRequests";
        if (!this.options.budget.tryConsume(kind)) { metrics.budgetTruncatedEndpoints = (metrics.budgetTruncatedEndpoints ?? 0) + 1; continue; }
      }
      const acc: EndpointAcc = {
        url: redactUrl(canonical),
        method: (ep.method ?? "GET").toUpperCase(),
        ...(ep.statusCode !== undefined ? { statusCode: ep.statusCode } : {}),
        ...(ep.contentLength !== undefined ? { contentLength: ep.contentLength } : {}),
        ...(ep.contentType ? { contentType: ep.contentType } : {}),
        ...(ep.title ? { title: ep.title } : {}),
        ...(ep.redirectLocation ? { redirectLocation: ep.redirectLocation } : {}),
        ...(ep.fingerprint ? { fingerprint: ep.fingerprint } : {}),
        parameterNames: ep.parameterNames ?? extractParameterNames(canonical),
        source: ep.source ?? tool,
        sourceSet: new Set([tool, ...(ep.sources ?? [])]),
        endpointType: ep.endpointType ?? classifyEndpointType(canonical),
        ...(ep.classification ?? sensitiveRouteLabel(canonical) ? { classification: ep.classification ?? sensitiveRouteLabel(canonical) } : {}),
        ...(wildcardUrls.has(ep.url) || ep.wildcardSuspect ? { wildcardSuspect: true } : {}),
        scopeStatus: this.scope.isUrlAllowed(canonical) ? "IN_SCOPE" : "OUT_OF_SCOPE",
      };
      endpoints.set(key, acc);
    }

    const endpointList: NormalizedEndpoint[] = [...endpoints.values()].map((acc) => {
      const { sourceSet, ...rest } = acc;
      return { ...rest, sources: [...sourceSet].sort() };
    });
    const inScopeKeys = new Set(endpointList.filter((e) => e.scopeStatus === "IN_SCOPE").map((e) => e.url.split("?")[0]));
    const parameterList: NormalizedEndpointParameter[] = [...parameters.values()]
      .filter((p) => inScopeKeys.has(p.endpointUrl)) // §28/§40: parameters only for in-scope endpoints
      .map((p) => {
        const { sourceSet, ...rest } = p;
        return { ...rest, sources: [...sourceSet].sort() };
      });

    metrics.duplicatesRemoved = duplicatesRemoved;
    metrics.endpointsInScope = endpointList.filter((e) => e.scopeStatus === "IN_SCOPE").length;
    metrics.outOfScopeRejected = endpointList.filter((e) => e.scopeStatus === "OUT_OF_SCOPE").length;
    metrics.apiEndpoints = endpointList.filter((e) => e.endpointType === "API").length;
    metrics.javascriptResources = endpointList.filter((e) => isJavaScriptResource(e.url)).length;
    metrics.parametersTotal = parameterList.length;

    return {
      assets: [], services: [], technologies: [],
      endpoints: endpointList,
      parameters: parameterList,
      forms: [...forms.values()],
      findings: [],
      artifacts: [],
      metrics,
      mock: inputs.length > 0 && inputs.every((i) => i.result.mock),
    };
  }
}
