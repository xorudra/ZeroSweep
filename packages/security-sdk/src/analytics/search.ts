import { redactForAi } from "../ai/redaction";

/**
 * Search indexing & snippet safety (Prompt 27 §21–§31, §111–§112,
 * §129–§130).
 *
 * Everything that enters the index passes the platform redaction
 * pipeline FIRST — a secret present in source evidence must be absent
 * from the index (§130). Snippets escape untrusted text (§129): an
 * indexed title containing HTML/script is data, never markup.
 */

export const MAX_SEARCHABLE_TEXT = 8_192;

export function buildSearchableText(parts: readonly (string | null | undefined)[]): string {
  const joined = parts.filter(Boolean).join("\n");
  const redacted = redactForAi(joined).text;
  return redacted.toLowerCase().replace(/\s+/g, " ").trim().slice(0, MAX_SEARCHABLE_TEXT);
}

/** Redact a display field (title/summary) without lowercasing. */
export function redactDisplayText(text: string): string {
  return redactForAi(text ?? "").text.slice(0, 2_048);
}

export function escapeSnippetHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

/**
 * Snippet around the first matching token — escaped AND redacted, so
 * it is safe to render and cannot leak a secret even if one somehow
 * reached a document (§25/§112/§129).
 */
export function makeSnippet(text: string, terms: readonly string[], windowChars = 160): string {
  const safe = redactForAi(text ?? "").text;
  const lower = safe.toLowerCase();
  let idx = -1;
  for (const t of terms) { const i = lower.indexOf(t.toLowerCase()); if (i >= 0 && (idx < 0 || i < idx)) idx = i; }
  let snippet: string;
  if (idx < 0) snippet = safe.slice(0, windowChars);
  else {
    const start = Math.max(0, idx - Math.floor(windowChars / 3));
    snippet = `${start > 0 ? "…" : ""}${safe.slice(start, start + windowChars)}${start + windowChars < safe.length ? "…" : ""}`;
  }
  return escapeSnippetHtml(snippet);
}

/** Token AND-match (§20 initial provider semantics): every query token must appear. */
export function matchesTokens(searchableText: string, tokens: readonly string[]): boolean {
  return tokens.every((t) => searchableText.includes(t.toLowerCase()));
}

export function queryTokens(query: string): string[] {
  return query.toLowerCase().split(/[^a-z0-9._-]+/i).map((t) => t.trim()).filter((t) => t.length > 0).slice(0, 16);
}

/** Facet counts over an ALREADY tenant+classification-scoped document set (§30). */
export function computeFacets<T>(docs: readonly T[], facetOf: (d: T) => Record<string, string | null | undefined>): Record<string, Array<{ value: string; count: number }>> {
  const out: Record<string, Map<string, number>> = {};
  for (const d of docs) {
    for (const [k, v] of Object.entries(facetOf(d))) {
      if (v == null || v === "") continue;
      const map = out[k] ?? (out[k] = new Map());
      map.set(v, (map.get(v) ?? 0) + 1);
    }
  }
  const result: Record<string, Array<{ value: string; count: number }>> = {};
  for (const [k, map] of Object.entries(out)) {
    result[k] = [...map.entries()].map(([value, count]) => ({ value, count })).sort((a, b) => b.count - a.count || (a.value < b.value ? -1 : 1)).slice(0, 25);
  }
  return result;
}

/**
 * Suggestions (§31) — computed ONLY over documents the caller already
 * scoped to the caller's tenant, so a suggestion can never leak a
 * cross-tenant name (§127).
 */
export function suggestValues(values: readonly string[], prefix: string, limit = 8): string[] {
  const p = prefix.toLowerCase();
  const seen = new Set<string>();
  const out: string[] = [];
  for (const v of values) {
    if (!v || seen.has(v)) continue;
    if (v.toLowerCase().includes(p)) { seen.add(v); out.push(v); if (out.length >= limit) break; }
  }
  return out;
}
