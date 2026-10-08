import type { EasmUrlClass } from "./types";

/**
 * Historical URL intelligence (Prompt 29 §59–§64). Historical URLs
 * are candidates, never auto-requested (§60). Classification is a
 * deterministic path heuristic (§61) — it does NOT imply a
 * vulnerability. Parameter handling stores NAMES only (§64):
 * values may carry tokens/session ids and are dropped on purpose.
 */

const STATIC_EXT = /\.(css|js|mjs|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|txt|xml|pdf|zip|gz|mp4|webm|avif)$/i;

export function classifyUrlPath(path: string): EasmUrlClass {
  const p = path.toLowerCase();
  if (STATIC_EXT.test(p)) return "STATIC";
  if (/\/(api|rest|graphql|v\d+(\/|$))/.test(p) || p.startsWith("/api")) return "API";
  if (/\/(login|logout|signin|signup|register|auth|oauth|sso|saml|password|reset-password|forgot)/.test(p)) return "AUTH";
  if (/\/(admin|administrator|manage|console|dashboard\/admin|wp-admin|phpmyadmin)/.test(p)) return "ADMIN";
  if (/\/(upload|uploads|file-upload|import|attach)/.test(p)) return "UPLOAD";
  return "UNKNOWN";
}

/** §64: parameter NAMES from a query string; values are discarded. */
export function parameterNames(query: string | null | undefined): string[] {
  if (!query) return [];
  const q = query.startsWith("?") ? query.slice(1) : query;
  const names = new Set<string>();
  for (const pair of q.split("&")) {
    if (!pair) continue;
    const name = pair.split("=")[0];
    if (name) {
      try { names.add(decodeURIComponent(name).slice(0, 80)); } catch { names.add(name.slice(0, 80)); }
    }
  }
  return [...names].sort();
}

export interface HistoricalUrlCandidate {
  url: string;
  classification: EasmUrlClass;
  parameterNames: string[];
}

/** §60: normalize + filter a raw historical URL list into candidates
 *  (bounded, de-duplicated, values stripped). */
export function normalizeHistoricalUrls(rawUrls: string[], limit = 500): HistoricalUrlCandidate[] {
  const seen = new Set<string>();
  const out: HistoricalUrlCandidate[] = [];
  for (const raw of rawUrls) {
    if (out.length >= limit) break;
    let url: URL;
    try { url = new URL(raw); } catch { continue; }
    if (url.protocol !== "http:" && url.protocol !== "https:") continue;
    const identity = `${url.protocol}//${url.host}${url.pathname}`;
    if (seen.has(identity)) continue;
    seen.add(identity);
    out.push({ url: identity, classification: classifyUrlPath(url.pathname), parameterNames: parameterNames(url.search) });
  }
  return out;
}
