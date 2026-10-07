import { ParserError } from "../adapter/adapter.errors";
import { canonicalizeHostname, canonicalizeUrl, extractParameterNames } from "./normalize";
import {
  emptyParsed, num, parseJsonLines, parseUrlLines, str, strArr,
  type ParsedRecon, type ReconParser,
} from "./parsers-common";

/**
 * Web-surface parsers (Prompt 5 §36): httpx, WhatWeb, gau, waybackurls,
 * Katana. HTTP statuses, titles, servers and technologies are SERVICE
 * METADATA (§10/§47) — none of these parsers can produce a finding.
 */

export class HttpxParser implements ReconParser {
  readonly tool = "httpx";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { records, warnings } = parseJsonLines(raw, this.tool);
    out.warnings.push(...warnings);
    for (const rec of records) {
      const urlRaw = str(rec.url) ?? str(rec.input) ?? "";
      const canonical = canonicalizeUrl(urlRaw.includes("://") ? urlRaw : `https://${urlRaw}`);
      const host = canonicalizeHostname(str(rec.host) ?? (canonical ? new URL(canonical).hostname : ""));
      if (!canonical || !host) { out.warnings.push("httpx: record without a valid URL/host skipped"); continue; }
      out.records++;
      const u = new URL(canonical);
      const port = num(rec.port) ?? (u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80);
      const scheme = str(rec.scheme) ?? u.protocol.replace(":", "");
      const statusCode = num(rec.status_code);
      const redirectRaw = str(rec.location) ?? str(rec.final_url);
      const redirectLocation = redirectRaw && redirectRaw !== canonical ? redirectRaw : undefined;
      const aRecs = strArr(rec.a);
      out.assets.push({ host, type: "HOST", sources: ["httpx"], ...(aRecs[0] ? { ip: aRecs[0] } : {}) });
      out.services.push({
        host, port, protocol: "tcp", name: scheme, scheme,
        ...(statusCode !== undefined ? { statusCode } : {}),
        ...(str(rec.title) ? { title: str(rec.title) } : {}),
        ...(str(rec.webserver) ? { server: str(rec.webserver) } : {}),
        ...(redirectLocation ? { redirectLocation } : {}),
      });
      out.endpoints.push({ url: canonical, method: "GET", ...(statusCode !== undefined ? { statusCode } : {}), parameterNames: extractParameterNames(canonical), source: "httpx" });
      for (const tech of strArr(rec.tech)) {
        out.technologies.push({ name: tech, host, category: "Technology", source: "httpx", confidence: 0.7 });
      }
      if (str(rec.webserver)) {
        out.technologies.push({ name: str(rec.webserver)!, host, category: "Web Server", source: "httpx", confidence: 0.9 });
      }
    }
    out.metrics.records = out.records;
    return out;
  }
}

const WHATWEB_CATEGORIES: Record<string, string> = {
  nginx: "Web Server", apache: "Web Server", "microsoft-iis": "Web Server", iis: "Web Server", lighttpd: "Web Server", openresty: "Web Server",
  wordpress: "CMS", drupal: "CMS", joomla: "CMS", magento: "CMS", ghost: "CMS",
  php: "Language", "asp.net": "Framework", node: "Framework", express: "Framework", django: "Framework", laravel: "Framework", "ruby-on-rails": "Framework",
  jquery: "JavaScript Library", react: "JavaScript Library", angular: "JavaScript Library", "vue.js": "JavaScript Library", bootstrap: "JavaScript Library",
  "google-analytics": "Analytics", "google-tag-manager": "Analytics",
};
export function whatwebCategory(name: string): string {
  return WHATWEB_CATEGORIES[name.toLowerCase()] ?? "Other";
}

export class WhatWebParser implements ReconParser {
  readonly tool = "whatweb";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const trimmed = raw.trim();
    if (!trimmed) return out;
    let parsed: unknown;
    try { parsed = JSON.parse(trimmed); } catch {
      // Brief stdout format: "https://host/ [200 OK] nginx[1.24.0], PHP[8.1]"
      const brief = parseWhatwebBrief(raw);
      if (brief.length > 0) {
        for (const entry of brief) {
          out.records++;
          out.endpoints.push({ url: entry.url, method: "GET", statusCode: entry.statusCode, parameterNames: extractParameterNames(entry.url), source: "whatweb" });
          const host = new URL(entry.url).hostname;
          for (const plugin of entry.plugins) {
            out.technologies.push({ name: plugin.name, host, category: whatwebCategory(plugin.name), source: "whatweb", ...(plugin.version ? { version: plugin.version } : {}), confidence: 0.7 });
          }
        }
        out.metrics.records = out.records;
        return out;
      }
      // WhatWeb also emits one JSON object per line in some modes.
      const { records, warnings } = parseJsonLines(raw, this.tool);
      out.warnings.push(...warnings);
      parsed = records;
      if (!Array.isArray(parsed) || (parsed as unknown[]).length === 0) {
        if (warnings.length === 0) throw new ParserError("whatweb: output is not valid JSON");
        return out;
      }
    }
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    for (const entry of entries) {
      if (!entry || typeof entry !== "object") { out.warnings.push("whatweb: non-object entry skipped"); continue; }
      const rec = entry as Record<string, unknown>;
      const target = str(rec.target) ?? "";
      const canonical = canonicalizeUrl(target);
      const host = canonical ? new URL(canonical).hostname : canonicalizeHostname(target);
      if (!host) { out.warnings.push("whatweb: entry without a valid target skipped"); continue; }
      out.records++;
      const statusCode = num(rec.http_status);
      if (canonical) out.endpoints.push({ url: canonical, method: "GET", ...(statusCode !== undefined ? { statusCode } : {}), parameterNames: extractParameterNames(canonical), source: "whatweb" });
      const plugins = (rec.plugins && typeof rec.plugins === "object") ? rec.plugins as Record<string, unknown> : {};
      for (const [name, info] of Object.entries(plugins)) {
        const detail = (info && typeof info === "object") ? info as Record<string, unknown> : {};
        const versions = strArr(detail.version);
        const certainty = num(detail.certainty);
        out.technologies.push({
          name, host, category: whatwebCategory(name), source: "whatweb",
          ...(versions[0] ? { version: versions[0] } : {}),
          confidence: certainty !== undefined ? Math.min(1, Math.max(0, certainty / 100)) : 0.8,
        });
      }
    }
    out.metrics.records = out.records;
    return out;
  }
}

/** WhatWeb "brief" lines: URL [status text] Plugin[version], Plugin, … */
export function parseWhatwebBrief(raw: string): { url: string; statusCode: number; plugins: { name: string; version?: string }[] }[] {
  const out: { url: string; statusCode: number; plugins: { name: string; version?: string }[] }[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^(https?:\/\/\S+)\s+\[(\d{3})[^\]]*\]\s*(.*)$/);
    if (!m) continue;
    const canonical = canonicalizeUrl(m[1]!);
    if (!canonical) continue;
    const plugins: { name: string; version?: string }[] = [];
    const tail = m[3] ?? "";
    for (const part of tail.split(/,\s*/)) {
      const pm = part.trim().match(/^([A-Za-z0-9_.+-]+)(?:\[([^\]]*)\])?$/);
      if (pm) plugins.push({ name: pm[1]!, ...(pm[2] ? { version: pm[2] } : {}) });
    }
    out.push({ url: canonical, statusCode: Number(m[2]), plugins });
  }
  return out;
}

export class GauParser implements ReconParser {
  readonly tool = "gau";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { endpoints, warnings, lines } = parseUrlLines(raw, this.tool, "gau");
    out.endpoints = endpoints;
    out.warnings.push(...warnings);
    out.records = endpoints.length;
    out.metrics.records = endpoints.length;
    out.metrics.lines = lines;
    return out;
  }
}

export class WaybackurlsParser implements ReconParser {
  readonly tool = "waybackurls";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { endpoints, warnings, lines } = parseUrlLines(raw, this.tool, "waybackurls");
    out.endpoints = endpoints;
    out.warnings.push(...warnings);
    out.records = endpoints.length;
    out.metrics.records = endpoints.length;
    out.metrics.lines = lines;
    return out;
  }
}

export class KatanaParser implements ReconParser {
  readonly tool = "katana";
  parse(raw: string): ParsedRecon {
    const out = emptyParsed();
    const { records, warnings } = parseJsonLines(raw, this.tool);
    out.warnings.push(...warnings);
    for (const rec of records) {
      const request = (rec.request && typeof rec.request === "object") ? rec.request as Record<string, unknown> : {};
      const response = (rec.response && typeof rec.response === "object") ? rec.response as Record<string, unknown> : {};
      const urlRaw = str(request.endpoint) ?? str(rec.endpoint) ?? str(rec.url) ?? "";
      const canonical = canonicalizeUrl(urlRaw);
      if (!canonical) { out.warnings.push("katana: record without a valid endpoint skipped"); continue; }
      out.records++;
      const statusCode = num(response.status_code) ?? num(rec.status_code);
      out.endpoints.push({
        url: canonical,
        method: str(request.method) ?? "GET",
        ...(statusCode !== undefined ? { statusCode } : {}),
        parameterNames: extractParameterNames(canonical),
        source: "katana",
      });
    }
    out.metrics.records = out.records;
    return out;
  }
}
