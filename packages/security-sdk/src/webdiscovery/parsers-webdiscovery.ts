import type { NormalizedEndpoint, NormalizedEndpointParameter } from "../findings/finding.types";
import { canonicalizeUrl, extractParameterNames } from "../recon/normalize";
import { emptyParsed, num, str, type ParsedRecon, type ReconParser } from "../recon/parsers-common";
import { responseFingerprint } from "./soft404";

/**
 * Parsers for the Prompt 6 web-discovery adapters (§37–§38). Each parser
 * validates the fields it depends on, tolerates optional/missing fields,
 * records malformed records as warnings instead of throwing, and emits
 * ONLY inventory (endpoints + parameter names) — never findings. Formats
 * differ across tool versions, so unknown top-level shapes degrade to a
 * warning + empty result rather than a crash.
 */

function endpoint(partial: Partial<NormalizedEndpoint> & { url: string; source: string }): NormalizedEndpoint | null {
  const canonical = canonicalizeUrl(partial.url);
  if (!canonical) return null;
  return {
    url: canonical,
    method: partial.method ?? "GET",
    ...(partial.statusCode !== undefined ? { statusCode: partial.statusCode } : {}),
    ...(partial.contentLength !== undefined ? { contentLength: partial.contentLength } : {}),
    ...(partial.contentType ? { contentType: partial.contentType } : {}),
    ...(partial.redirectLocation ? { redirectLocation: partial.redirectLocation } : {}),
    parameterNames: partial.parameterNames ?? extractParameterNames(canonical),
    source: partial.source,
    fingerprint: responseFingerprint({
      statusCode: partial.statusCode, contentLength: partial.contentLength, contentType: partial.contentType,
    }),
  };
}

/** ffuf `-of json` document: { results: [{ url, status, length, words,
 *  lines, "content-type", redirectlocation, host }] } (§3). */
export class FfufParser implements ReconParser {
  readonly tool = "ffuf";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    if (!raw.trim()) return out;
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch {
      out.warnings.push("ffuf: output is not valid JSON — unsupported format, no results recorded");
      return out;
    }
    const results = (doc as { results?: unknown }).results;
    if (!Array.isArray(results)) {
      out.warnings.push("ffuf: JSON document has no results array — unsupported format version");
      return out;
    }
    for (const [i, r] of results.entries()) {
      const rec = r as Record<string, unknown>;
      const url = str(rec.url);
      if (!url) { out.warnings.push(`ffuf: result ${i + 1} missing url — skipped`); continue; }
      const ep = endpoint({
        url, source: "ffuf",
        statusCode: num(rec.status),
        contentLength: num(rec.length),
        contentType: str(rec["content-type"]),
        redirectLocation: str(rec.redirectlocation),
      });
      if (ep) {
        ep.fingerprint = responseFingerprint({
          statusCode: num(rec.status), contentLength: num(rec.length),
          wordCount: num(rec.words), lineCount: num(rec.lines), contentType: str(rec["content-type"]),
        });
        out.endpoints.push(ep);
        out.records++;
      }
    }
    out.metrics = { endpoints: out.endpoints.length };
    return out;
  }
}

/** Feroxbuster `--json` line stream: {"type":"response","url":…,"status":…,
 *  "content_length":…,"line_count":…,"word_count":…} interleaved with
 *  statistics/log records, which are ignored (§4). */
export class FeroxbusterParser implements ReconParser {
  readonly tool = "feroxbuster";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    for (const [i, line] of raw.split(/\r?\n/).entries()) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (!trimmed.startsWith("{")) { out.warnings.push(`feroxbuster: skipped non-JSON line ${i + 1}`); continue; }
      let rec: Record<string, unknown>;
      try { rec = JSON.parse(trimmed) as Record<string, unknown>; } catch {
        out.warnings.push(`feroxbuster: invalid JSON on line ${i + 1}`);
        continue;
      }
      if (rec.type !== "response") continue; // statistics / log records are not endpoints
      const url = str(rec.url);
      if (!url) { out.warnings.push(`feroxbuster: response record ${i + 1} missing url — skipped`); continue; }
      const status = num(rec.status) ?? num(rec.status_code);
      const ep = endpoint({
        url, source: "feroxbuster", statusCode: status, contentLength: num(rec.content_length),
      });
      if (ep) {
        ep.fingerprint = responseFingerprint({
          statusCode: status, contentLength: num(rec.content_length),
          wordCount: num(rec.word_count), lineCount: num(rec.line_count),
        });
        out.endpoints.push(ep);
        out.records++;
      }
    }
    out.metrics = { endpoints: out.endpoints.length };
    return out;
  }
}

/** Gobuster dir text (§5): "/admin (Status: 200) [Size: 1234]" and
 *  "/old (Status: 301) [Size: 177] [--> https://example.com/old/]".
 *  Gobuster reports PATHS, so the parser is constructed with the plan's
 *  base URL to absolutize them — the base comes from the validated plan,
 *  never from the tool output. */
export class GobusterParser implements ReconParser {
  readonly tool = "gobuster";
  constructor(private readonly baseUrl?: string) {}
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const lineRe = /^(\S+)\s+\(Status:\s*(\d{3})\)\s*\[Size:\s*(\d+)\](?:\s*\[-->\s*(\S+)\])?/;
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const m = trimmed.match(lineRe);
      if (!m) {
        if (!trimmed.startsWith("[") && !trimmed.startsWith("=") && !/^Gobuster/i.test(trimmed)) {
          out.warnings.push(`gobuster: skipped unrecognized line "${trimmed.slice(0, 80)}"`);
        }
        continue;
      }
      const [, path, status, size, redirect] = m;
      const absolute = path!.startsWith("http") ? path! : this.baseUrl ? new URL(path!, this.baseUrl).toString() : undefined;
      if (!absolute) { out.warnings.push(`gobuster: cannot absolutize "${path}" without a base URL — skipped`); continue; }
      const ep = endpoint({
        url: absolute, source: "gobuster",
        statusCode: Number(status), contentLength: Number(size),
        redirectLocation: redirect,
      });
      if (ep) { out.endpoints.push(ep); out.records++; }
    }
    out.metrics = { endpoints: out.endpoints.length };
    return out;
  }
}

/** Wfuzz JSON result list (§6/§29): entries carry the fuzzed url, status
 *  `code` and the payload (`payload`, older versions use `description`).
 *  Path-fuzzing entries become endpoints; query-key payloads from the
 *  predefined PARAMETER template additionally become parameter records —
 *  the payload VALUE itself is never stored as anything but a path/name. */
export class WfuzzParser implements ReconParser {
  readonly tool = "wfuzz";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    if (!raw.trim()) return out;
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch {
      out.warnings.push("wfuzz: output is not valid JSON — unsupported format, no results recorded");
      return out;
    }
    if (!Array.isArray(doc)) {
      out.warnings.push("wfuzz: JSON document is not a result array — unsupported format version");
      return out;
    }
    const params = new Map<string, NormalizedEndpointParameter>();
    for (const [i, entry] of doc.entries()) {
      const rec = entry as Record<string, unknown>;
      const url = str(rec.url);
      if (!url) { out.warnings.push(`wfuzz: result ${i + 1} missing url — skipped`); continue; }
      const ep = endpoint({
        url, source: "wfuzz", statusCode: num(rec.code), contentLength: num(rec.chars),
      });
      if (!ep) continue;
      ep.fingerprint = responseFingerprint({
        statusCode: num(rec.code), contentLength: num(rec.chars),
        wordCount: num(rec.words), lineCount: num(rec.lines),
      });
      out.endpoints.push(ep);
      out.records++;
      // Parameter template: the fuzzed URL is <endpoint>?<name>=<value> —
      // the NAME joins parameter inventory for the base endpoint (§29).
      const canonical = canonicalizeUrl(url);
      if (canonical) {
        const names = extractParameterNames(canonical);
        const base = canonical.split("?")[0]!;
        for (const name of names) {
          const key = `${base}|${name}`;
          if (!params.has(key)) {
            params.set(key, { endpointUrl: base, name, location: "QUERY", sources: ["wfuzz"], confidence: 0.8 });
          }
        }
      }
    }
    out.parameters = [...params.values()];
    out.metrics = { endpoints: out.endpoints.length, parameters: out.parameters.length };
    return out;
  }
}

/** Arjun JSON (§7/§28): { "<url>": { "params": ["id", "page"] } } (current
 *  format) — an array of { url, params } is also tolerated (§38). Only
 *  parameter NAMES are read; arjun's per-parameter detail values are
 *  deliberately ignored. */
export class ArjunParser implements ReconParser {
  readonly tool = "arjun";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    if (!raw.trim()) return out;
    let doc: unknown;
    try { doc = JSON.parse(raw); } catch {
      out.warnings.push("arjun: output is not valid JSON — unsupported format, no results recorded");
      return out;
    }
    const pairs: Array<{ url: string; params: string[] }> = [];
    if (Array.isArray(doc)) {
      for (const entry of doc) {
        const rec = entry as Record<string, unknown>;
        const url = str(rec.url);
        const params = Array.isArray(rec.params) ? rec.params.filter((p): p is string => typeof p === "string") : [];
        if (url) pairs.push({ url, params });
      }
    } else if (doc && typeof doc === "object") {
      for (const [url, value] of Object.entries(doc as Record<string, unknown>)) {
        const paramsRaw = (value as { params?: unknown })?.params;
        const params = Array.isArray(paramsRaw) ? paramsRaw.filter((p): p is string => typeof p === "string") : [];
        pairs.push({ url, params });
      }
    } else {
      out.warnings.push("arjun: JSON document has an unsupported shape — no results recorded");
      return out;
    }
    const params: NormalizedEndpointParameter[] = [];
    for (const pair of pairs) {
      const canonical = canonicalizeUrl(pair.url);
      if (!canonical) { out.warnings.push(`arjun: skipped malformed URL "${pair.url.slice(0, 80)}"`); continue; }
      const names = [...new Set(pair.params.map((p) => p.trim()).filter((p) => /^[a-zA-Z0-9_.\-\x5B\x5D]+$/.test(p)))].sort();
      const ep = endpoint({ url: canonical, source: "arjun", parameterNames: names });
      if (ep) { out.endpoints.push(ep); out.records++; }
      for (const name of names) {
        params.push({ endpointUrl: canonical.split("?")[0]!, name, location: "QUERY", sources: ["arjun"], confidence: 0.9 });
      }
    }
    out.parameters = params;
    out.metrics = { endpoints: out.endpoints.length, parameters: params.length };
    return out;
  }
}
