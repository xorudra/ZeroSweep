import type { NormalizedAsset, NormalizedEndpoint, NormalizedService, NormalizedTechnology } from "../findings/finding.types";
import { canonicalizeHostname, canonicalizeUrl, extractParameterNames } from "./normalize";

/**
 * Shared parser contract for recon adapters (Prompt 5 §36–§37). A parser
 * turns one tool's raw output into normalized fragments + counts. Parsers
 * NEVER throw on malformed records: bad lines become warnings, good records
 * survive — one corrupt line must not kill a scan.
 */
export interface ParsedRecon {
  assets: NormalizedAsset[];
  services: NormalizedService[];
  endpoints: NormalizedEndpoint[];
  technologies: NormalizedTechnology[];
  /** Records successfully interpreted (before dedupe). */
  records: number;
  warnings: string[];
  metrics: Record<string, number>;
  /** dnsx only: A/AAAA answers of the wildcard probe label (Prompt 5 §29). */
  wildcardIpSet?: string[];
}

export function emptyParsed(): ParsedRecon {
  return { assets: [], services: [], endpoints: [], technologies: [], records: 0, warnings: [], metrics: {} };
}

export interface ReconParser {
  readonly tool: string;
  parse(raw: string): ParsedRecon;
}

/** Split JSONL output into records, tolerating blank lines, tool banners and
 *  individual malformed lines (each becomes a parser warning, §37). */
export function parseJsonLines(raw: string, tool: string): { records: Record<string, unknown>[]; warnings: string[] } {
  const records: Record<string, unknown>[] = [];
  const warnings: string[] = [];
  const lines = raw.split(/\r?\n/);
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    if (!trimmed.startsWith("{")) {
      warnings.push(`${tool}: skipped non-JSON line ${i + 1}`);
      return;
    }
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) records.push(parsed as Record<string, unknown>);
      else warnings.push(`${tool}: line ${i + 1} is not a JSON object`);
    } catch {
      warnings.push(`${tool}: invalid JSON on line ${i + 1}`);
    }
  });
  return { records, warnings };
}

/** Plain-text host list (assetfinder/findomain style): one host per line,
 *  with banner/comment tolerance. Hostnames are canonicalized + deduped by
 *  the aggregator later; here we only validate shape. */
export function parseHostLines(raw: string, tool: string): { hosts: string[]; warnings: string[] } {
  const hosts: string[] = [];
  const warnings: string[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("[")) continue;
    // findomain without -q prefixes lines with human text; extract the first
    // hostname-looking token instead of trusting the whole line.
    const token = trimmed.split(/\s+/).map((t) => t.replace(/^[>*\-–—\s]+/, "")).find((t) => t.includes(".")) ?? trimmed;
    const host = canonicalizeHostname(token);
    if (host) hosts.push(host);
    else warnings.push(`${tool}: skipped malformed host line "${trimmed.slice(0, 80)}"`);
  }
  return { hosts, warnings };
}

/** Plain-text URL list (gau/waybackurls style). Returns canonical URLs;
 *  unparseable or non-http(s) lines become warnings (§37). */
export function parseUrlLines(raw: string, tool: string, source: string): { endpoints: NormalizedEndpoint[]; warnings: string[]; lines: number } {
  const endpoints: NormalizedEndpoint[] = [];
  const warnings: string[] = [];
  let lines = 0;
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    lines++;
    const canonical = canonicalizeUrl(trimmed);
    if (!canonical) {
      warnings.push(`${tool}: skipped malformed URL line "${trimmed.slice(0, 80)}"`);
      continue;
    }
    endpoints.push({ url: canonical, parameterNames: extractParameterNames(canonical), source });
  }
  return { endpoints, warnings, lines };
}

export function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
export function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
export function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
}
