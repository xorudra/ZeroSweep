import type { EndpointType } from "../findings/finding.types";
import { canonicalizeUrl } from "../recon/normalize";

/**
 * Route classification, normalization and explosion protection
 * (Prompt 6 §21, §41–§47). Everything here is deterministic inventory
 * hygiene: probable API routes are labelled API, admin-style routes are
 * labelled SENSITIVE_ROUTE *for prioritization* — neither label is ever a
 * vulnerability claim (§41/§42).
 */

const API_PATH_RE = /(^|\/)(api|rest|graphql)(\/|$)|(^|\/)v[0-9]+(\/|$)/i;
const SENSITIVE_SEGMENTS = new Set([
  "admin", "administrator", "dashboard", "management", "manage", "console",
  "cpanel", "wp-admin", "phpmyadmin", "actuator", "server-status", "config",
  "settings", "backend", "internal-admin",
]);
const STATIC_EXTENSIONS = new Set([
  "css", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2", "ttf",
  "eot", "map", "mp4", "webm", "mp3", "wav", "avi", "mov", "pdf", "zip",
]);
const FILE_EXTENSIONS = new Set([
  "txt", "xml", "json", "html", "htm", "php", "asp", "aspx", "jsp", "md",
]);

export function pathOf(url: string): string {
  try { return new URL(url).pathname; } catch { return url; }
}
export function extensionOf(url: string): string {
  const path = pathOf(url);
  const last = path.split("/").pop() ?? "";
  const dot = last.lastIndexOf(".");
  return dot > 0 ? last.slice(dot + 1).toLowerCase() : "";
}

/** Probable API route (§41): /api/, /api/v1/, /graphql, /rest/, /v1/, /v2/. */
export function isApiRoute(url: string): boolean {
  return API_PATH_RE.test(pathOf(url));
}

/** Admin-style route classification (§42) — SENSITIVE_ROUTE is an
 *  inventory/prioritization label only. */
export function sensitiveRouteLabel(url: string): string | undefined {
  const segments = pathOf(url).split("/").filter(Boolean).map((s) => s.toLowerCase());
  return segments.some((s) => SENSITIVE_SEGMENTS.has(s)) ? "SENSITIVE_ROUTE" : undefined;
}

/** Obvious static resources (§43): deprioritized for downstream testing
 *  budget, kept in inventory (JS files are inventoried for a later phase, §44). */
export function isStaticResource(url: string): boolean {
  const ext = extensionOf(url);
  return STATIC_EXTENSIONS.has(ext) || ext === "js" || ext === "mjs";
}
export function isJavaScriptResource(url: string): boolean {
  return extensionOf(url) === "js" || extensionOf(url) === "mjs";
}

/** Route kind for inventory (§41/§43/§22): API beats static beats file;
 *  a trailing slash or extensionless deep path reads as a directory/page. */
export function classifyEndpointType(url: string): EndpointType {
  if (isApiRoute(url)) return "API";
  const ext = extensionOf(url);
  if (isStaticResource(url) || ext === "js" || ext === "mjs") return "STATIC";
  if (ext && FILE_EXTENSIONS.has(ext)) return "FILE";
  const path = pathOf(url);
  if (path.endsWith("/") && path !== "/") return "DIRECTORY";
  return "PAGE";
}

/**
 * Directory normalization (§21): /admin, /admin/ and /ADMIN are recorded
 * with their original evidence preserved; the CANONICAL LOOKUP FORM is
 * lowercased with a single trailing slash — used for comparison only,
 * never to rewrite the stored endpoint.
 */
export function canonicalLookupForm(url: string): string {
  const canonical = canonicalizeUrl(url) ?? url;
  try {
    const u = new URL(canonical);
    const path = u.pathname.toLowerCase().replace(/\/{2,}/g, "/");
    return `${u.origin}${path.endsWith("/") ? path : `${path}/`}${u.search}`;
  } catch {
    return canonical.toLowerCase();
  }
}

/**
 * Duplicate-URL control (§45): URLs differing only in volatile VALUES
 * collapse to one representative — identity is origin + path + parameter
 * NAMES (values are evidence, sampled once, never an identity).
 */
export function volatileUrlKey(url: string): string {
  try {
    const u = new URL(url);
    const names = [...new Set([...u.searchParams.keys()])].sort().join(",");
    return `${u.origin}${u.pathname}|${names}`;
  } catch {
    return url;
  }
}

const SESSION_SEGMENT_RE = /(session|sid|token|auth|key)=|^[a-f0-9]{24,}$|^[a-z0-9_-]{28,}$/i;
const NUMERIC_SEGMENT_RE = /^\d+$/;

export interface TrapVerdict {
  trap: boolean;
  reasons: string[];
}

/**
 * Crawler-trap detection (§46/§47): ever-increasing page numbers, deep
 * repeated structures, high-entropy/session segments and unbounded
 * pagination are expansion traps. Verdicts are heuristics over the URL
 * shape plus the count of siblings already seen under the same parent.
 */
export function detectCrawlerTrap(url: string, opts: { siblingsSeen?: number; maxDepth?: number; maxSiblings?: number } = {}): TrapVerdict {
  const reasons: string[] = [];
  const maxDepth = opts.maxDepth ?? 8;
  const maxSiblings = opts.maxSiblings ?? 500;
  let segments: string[] = [];
  let searchParams: URLSearchParams | undefined;
  try {
    const u = new URL(url);
    segments = u.pathname.split("/").filter(Boolean);
    searchParams = u.searchParams;
  } catch {
    return { trap: true, reasons: ["unparseable URL"] };
  }
  if (segments.length > maxDepth) reasons.push(`path depth ${segments.length} exceeds ${maxDepth}`);
  const counts = new Map<string, number>();
  for (const s of segments) counts.set(s, (counts.get(s) ?? 0) + 1);
  if ([...counts.values()].some((n) => n >= 3)) reasons.push("path segment repeats 3+ times (loop structure)");
  if (segments.some((s) => SESSION_SEGMENT_RE.test(s))) reasons.push("high-entropy or session-like path segment");
  if (searchParams) {
    for (const key of ["page", "p", "offset", "cursor"]) {
      const v = searchParams.get(key);
      if (v && /^\d+$/.test(v) && Number(v) > 10_000) reasons.push(`pagination parameter ${key}=${v} is implausibly deep`);
    }
    // NOTE: a session/token NAME in a query string is NOT a trap signal on
    // its own — real login/session URLs carry them and are legitimate
    // inventory (values are redacted at storage). Trap verdicts rest on
    // structure: depth, repetition, entropy segments, sibling explosions.
  }
  if ((opts.siblingsSeen ?? 0) > maxSiblings) reasons.push(`more than ${maxSiblings} sibling URLs under one parent (calendar/pagination explosion)`);
  return { trap: reasons.length > 0, reasons };
}

export function isNumericSegment(segment: string): boolean {
  return NUMERIC_SEGMENT_RE.test(segment);
}

/**
 * Arjun target prioritization (§28): parameter discovery is fed ONLY
 * eligible endpoints — live before historical, GET before other methods,
 * API-looking routes first, no static resources, no out-of-scope entries.
 * Pure ordering over inventory records; scope is re-checked by callers.
 */
export function prioritizeParameterTargets<T extends { url: string; method?: string; scopeStatus?: string; statusCode?: number }>(
  endpoints: readonly T[],
  limit = 50,
): T[] {
  const score = (e: T): number => {
    let s = 0;
    if (isApiRoute(e.url)) s += 40;
    if ((e.method ?? "GET").toUpperCase() === "GET") s += 20;
    if (e.statusCode !== undefined && e.statusCode < 400) s += 10;
    if (isStaticResource(e.url)) s -= 100;
    return s;
  };
  return endpoints
    .filter((e) => e.scopeStatus !== "OUT_OF_SCOPE" && !isStaticResource(e.url))
    .sort((a, b) => score(b) - score(a))
    .slice(0, Math.max(0, limit));
}

/**
 * robots.txt parser (§24): Allow/Disallow/Sitemap directives. Disallowed
 * routes still enter inventory (they are attack-surface knowledge) and
 * still require scope validation downstream — robots.txt is a hint from
 * the operator, not an authorization.
 */
export function parseRobotsTxt(text: string): { disallow: string[]; allow: string[]; sitemaps: string[] } {
  const disallow: string[] = [];
  const allow: string[] = [];
  const sitemaps: string[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const field = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!value) continue;
    if (field === "disallow") disallow.push(value);
    else if (field === "allow") allow.push(value);
    else if (field === "sitemap") sitemaps.push(value);
  }
  return { disallow, allow, sitemaps };
}

/**
 * Sitemap parser (§25): bounded recursion — nested sitemap indexes are
 * returned as `childSitemaps` for the CALLER to fetch within budget; this
 * parser itself never expands beyond the document it was handed, and the
 * location count is capped.
 */
export function parseSitemapXml(xml: string, maxLocations = 5_000): { locations: string[]; childSitemaps: string[] } {
  const locs = [...xml.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/gi)].map((m) => m[1]!.trim()).filter(Boolean);
  // A sitemap INDEX lists child sitemaps; a urlset lists page locations.
  const isIndex = /<sitemapindex[\s>]/i.test(xml);
  return isIndex
    ? { locations: [], childSitemaps: locs.slice(0, maxLocations) }
    : { locations: locs.slice(0, maxLocations), childSitemaps: [] };
}
