import { createHash } from "node:crypto";
import type { NormalizedEndpoint, NormalizedHttpTransaction, NormalizedWebSocket } from "../findings/finding.types";
import { canonicalizeHostname, canonicalizeUrl, extractParameterNames } from "../recon/normalize";
import { str } from "../recon/parsers-common";
import { makeFinding } from "../vuln/parsers-vuln";
import type { ParsedObservation } from "../vuln/parsers-vuln";
import type { NormalizedVulnFinding } from "../vuln/types";
import { classifyApiKind, isGraphQlEndpoint, isOpenApiDocumentUrl, isWebSocketUrl } from "./classify";
import { MAX_IMPORT_RECORDS, parseXmlDocument, xmlChild, xmlChildren, xmlText, type XmlNode } from "./import-security";
import { HttpEvidenceRedactor, httpEvidenceRedactor } from "./redactor";
import { mapBurpConfidence, mapBurpSeverity, mapCaidoSeverity, mapZapConfidence, mapZapSeverity } from "./severity";

/**
 * Proxy/scanner issue parsers (Prompt 8 §32). One parser per product —
 * ZapIssueParser, BurpIssueParser, CaidoIssueParser — each translating its
 * product's native export into the EXISTING normalized finding schema via
 * the shared makeFinding() assembler, so imported issues get taxonomy
 * CWE/OWASP, curated remediation and canonical fingerprints identical in
 * construction to Nuclei/Nikto findings. That is what lets the Phase 7
 * correlation engine merge a ZAP or Burp report of an issue with the
 * Nuclei/Nikto report of the SAME issue (§33/§36).
 *
 * Parsers also build the transaction/endpoint inventory (§25/§30):
 * requests/responses become NormalizedHttpTransactions whose display
 * copies are redacted by HttpEvidenceRedactor (§27) and whose raw bytes
 * are only hashed + sized here — the raw artifact itself is stored by the
 * caller in object storage (§26).
 */

export interface ParsedProxy {
  findings: NormalizedVulnFinding[];
  endpoints: NormalizedEndpoint[];
  transactions: NormalizedHttpTransaction[];
  webSockets: NormalizedWebSocket[];
  observations: ParsedObservation[];
  records: number;
  warnings: string[];
  metrics: Record<string, number>;
}

export function emptyParsedProxy(): ParsedProxy {
  return { findings: [], endpoints: [], transactions: [], webSockets: [], observations: [], records: 0, warnings: [], metrics: {} };
}

const sha256 = (s: string): string => createHash("sha256").update(s).digest("hex");

export function hostPortOf(url: string): { host?: string; port?: number; protocol: string } {
  try {
    const u = new URL(url);
    return {
      host: canonicalizeHostname(u.hostname) ?? u.hostname.toLowerCase(),
      port: u.port ? Number(u.port) : undefined,
      protocol: u.protocol.replace(":", ""),
    };
  } catch {
    return { protocol: "https" };
  }
}

/** Build one normalized transaction from raw request/response text. Raw
 *  text is hashed + measured; only the REDACTED display copy is carried
 *  forward (§26/§27). */
export function toTransaction(
  input: {
    method?: string; url: string; statusCode?: number; timestamp?: string; durationMs?: number;
    requestRaw?: string; responseRaw?: string; source: string;
  },
  redactor: HttpEvidenceRedactor = httpEvidenceRedactor,
): NormalizedHttpTransaction | null {
  const canonical = canonicalizeUrl(input.url);
  if (!canonical) return null;
  let host = "";
  let path = "/";
  try {
    const u = new URL(canonical);
    host = u.hostname;
    path = u.pathname || "/";
  } catch { return null; }
  const req = input.requestRaw ? redactor.redactHttpMessage(input.requestRaw) : undefined;
  const res = input.responseRaw ? redactor.redactHttpMessage(input.responseRaw) : undefined;
  return {
    method: (input.method ?? "GET").toUpperCase(),
    url: canonical,
    host,
    path,
    ...(input.statusCode !== undefined ? { statusCode: input.statusCode } : {}),
    source: input.source,
    ...(input.timestamp ? { timestamp: input.timestamp } : {}),
    ...(input.durationMs !== undefined ? { durationMs: input.durationMs } : {}),
    ...(req ? { requestSize: req.originalBytes, requestHash: req.checksum, requestRedacted: req.text } : {}),
    ...(res ? { responseSize: res.originalBytes, responseHash: res.checksum, responseRedacted: res.text } : {}),
  };
}

/** Curated issue-name → vulnerability-class mapping shared by the proxy
 *  parsers (§32/§36): correlation keys on the CLASS, so a Burp issue named
 *  "Content Security Policy not set" and a ZAP alert with the same name
 *  land in the same class Nuclei uses. Conservative: no match means
 *  GENERIC_VULNERABILITY, never a guessed specific class. */
const NAME_CLASS_PATTERNS: Array<[RegExp, string]> = [
  [/content security policy/i, "MISSING_SECURITY_HEADERS"],
  [/x-frame-options|clickjacking|frameable/i, "MISSING_SECURITY_HEADERS"],
  [/strict-transport-security|\bhsts\b/i, "MISSING_SECURITY_HEADERS"],
  [/x-content-type-options|mime.*sniff/i, "MISSING_SECURITY_HEADERS"],
  [/permissions policy/i, "MISSING_SECURITY_HEADERS"],
  [/cookie.*httponly|httponly.*cookie/i, "COOKIE_NO_HTTPONLY"],
  [/cookie.*secure flag|secure flag.*cookie/i, "COOKIE_NO_SECURE"],
  [/samesite/i, "COOKIE_NO_SAMESITE"],
  [/directory listing|directory browsing/i, "DIRECTORY_LISTING"],
  [/cross-domain misconfiguration|cross-origin resource sharing|\bcors\b/i, "CORS_MISCONFIGURATION"],
  [/open redirect|unvalidated redirect/i, "OPEN_REDIRECT"],
  [/cross-site scripting|\bxss\b/i, "XSS"],
  [/outdated|unpatched|vulnerable.*version/i, "OUTDATED_SOFTWARE"],
  [/sensitive file|exposed file/i, "EXPOSED_FILE"],
  [/information disclosure|information leak|sensitive information/i, "INFORMATION_DISCLOSURE"],
  [/weak tls|tls.*(deprecated|weak)|ssl.*(deprecated|weak protocol)/i, "TLS_WEAK_PROTOCOL"],
];

export function vulnClassForIssueName(name: string): string {
  for (const [re, cls] of NAME_CLASS_PATTERNS) if (re.test(name)) return cls;
  return "GENERIC_VULNERABILITY";
}

function endpointFromUrl(url: string, source: string, method?: string, statusCode?: number): NormalizedEndpoint | null {
  const canonical = canonicalizeUrl(url);
  if (!canonical) return null;
  return {
    url: canonical,
    method: (method ?? "GET").toUpperCase(),
    ...(statusCode !== undefined ? { statusCode } : {}),
    parameterNames: extractParameterNames(canonical),
    source,
    sources: [source],
  };
}

// ------------------------------- ZAP (§32) -------------------------------

/** ZAP passive-scan plugin ids with a curated class mapping. Anything not
 *  listed falls back to the issue-name mapping, then GENERIC. Plugin ids
 *  are from ZAP's passive scan rules add-on (stable, documented ids). */
export const ZAP_PLUGIN_CLASS: Record<string, string> = {
  "10010": "COOKIE_NO_HTTPONLY",
  "10011": "COOKIE_NO_SECURE",
  "10054": "COOKIE_NO_SAMESITE",
  "10020": "MISSING_SECURITY_HEADERS",
  "10021": "MISSING_SECURITY_HEADERS",
  "10035": "MISSING_SECURITY_HEADERS",
  "10038": "MISSING_SECURITY_HEADERS",
  "10063": "MISSING_SECURITY_HEADERS",
  "10033": "DIRECTORY_LISTING",
  "10098": "CORS_MISCONFIGURATION",
  "10023": "INFORMATION_DISCLOSURE",
  "10024": "INFORMATION_DISCLOSURE",
  "10025": "INFORMATION_DISCLOSURE",
  "10027": "INFORMATION_DISCLOSURE",
  "10052": "INFORMATION_DISCLOSURE",
  "10056": "INFORMATION_DISCLOSURE",
  "10061": "INFORMATION_DISCLOSURE",
  "10096": "INFORMATION_DISCLOSURE",
  "10040": "SERVER_MISCONFIGURATION",
  "10015": "SERVER_MISCONFIGURATION",
};

export interface ZapAlertInstance {
  uri?: string; method?: string; param?: string; attack?: string; evidence?: string;
}
export interface ZapAlert {
  pluginId?: string; alert?: string; name?: string; riskcode?: string; confidence?: string;
  riskdesc?: string; desc?: string; solution?: string; otherinfo?: string; reference?: string;
  cweid?: string; instances?: ZapAlertInstance[];
}

/** Accepts the three shapes ZAP produces alerts in: the API view
 *  ({ alerts: [...] }), a bare array, and the JSON report
 *  ({ site: [ { alerts: [...] } ] }). */
export function extractZapAlerts(payload: unknown): ZapAlert[] {
  if (Array.isArray(payload)) return payload as ZapAlert[];
  if (payload && typeof payload === "object") {
    const p = payload as Record<string, unknown>;
    if (Array.isArray(p.alerts)) return p.alerts as ZapAlert[];
    if (Array.isArray(p.site)) {
      const out: ZapAlert[] = [];
      for (const site of p.site as Array<Record<string, unknown>>) {
        if (Array.isArray(site.alerts)) out.push(...(site.alerts as ZapAlert[]));
      }
      return out;
    }
  }
  return [];
}

export class ZapIssueParser {
  readonly tool = "owasp-zap";

  parse(payload: unknown, opts: { maxInstancesPerAlert?: number } = {}): ParsedProxy {
    const out = emptyParsedProxy();
    const alerts = extractZapAlerts(payload);
    out.records = alerts.length;
    if (alerts.length > MAX_IMPORT_RECORDS) out.warnings.push(`ZAP alerts truncated at ${MAX_IMPORT_RECORDS} records (§62)`);
    const maxInstances = opts.maxInstancesPerAlert ?? 25;
    for (const alert of alerts.slice(0, MAX_IMPORT_RECORDS)) {
      const name = alert.alert ?? alert.name ?? "ZAP alert";
      const pluginId = alert.pluginId ?? "";
      const vulnClass = ZAP_PLUGIN_CLASS[pluginId] ?? vulnClassForIssueName(name);
      // Modern-app / informational detection rules are observations, not
      // findings (§7: do not treat every alert as a finding at all).
      if (pluginId === "10109" || pluginId === "10111" || pluginId === "10112") {
        out.observations.push({ kind: "INFORMATIONAL", summary: `ZAP: ${name}` });
        continue;
      }
      const severity = mapZapSeverity(alert.riskcode, alert.riskdesc);
      const confidence = mapZapConfidence(alert.confidence);
      const instances = (alert.instances ?? []).slice(0, maxInstances);
      const effective = instances.length > 0 ? instances : [{} as ZapAlertInstance];
      for (const inst of effective) {
        const uri = inst.uri;
        const hp = uri ? hostPortOf(uri) : { protocol: "https" };
        out.findings.push(makeFinding({
          title: name,
          description: (alert.desc ?? name).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim(),
          severity,
          vulnClass,
          ...(hp.host ? { host: hp.host } : {}),
          ...(hp.port !== undefined ? { port: hp.port } : {}),
          protocol: hp.protocol,
          ...(uri ? { endpoint: uri } : {}),
          ...(inst.param ? { parameter: inst.param } : {}),
          ...(alert.cweid && /^\d+$/.test(alert.cweid) ? { cwe: `CWE-${alert.cweid}` } : {}),
          ...(alert.solution ? { remediation: alert.solution.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() } : {}),
          referenceUrls: alert.reference ? alert.reference.split(/[\s,]+/).filter(Boolean) : [],
          sourceTool: this.tool,
          sourceConfidence: confidence.score,
          templateId: pluginId || undefined,
          signatureFamily: pluginId ? `zap-plugin:${pluginId}` : "zap-passive",
          evidenceSummary: `ZAP passive alert ${pluginId || ""} on ${uri ?? "target"}${inst.evidence ? `: ${inst.evidence.slice(0, 200)}` : ""}`,
          evidenceDetail: {
            ...(uri ? { matchedAt: uri } : {}),
            checkId: pluginId || undefined,
            signatureFamily: pluginId ? `zap-plugin:${pluginId}` : "zap-passive",
            metadata: {
              scannerProduct: "ZAP",
              issueType: pluginId || name,
              confidenceLabel: confidence.label,
              ...(alert.otherinfo ? { scannerNotes: alert.otherinfo.replace(/<[^>]+>/g, " ").slice(0, 500) } : {}),
            },
          },
        }));
      }
    }
    out.metrics = { alerts: alerts.length, findings: out.findings.length, observations: out.observations.length };
    return out;
  }
}

// ------------------------------- Burp (§32) -------------------------------

function decodeBase64(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const compact = value.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(compact) || compact.length % 4 === 1) return undefined;
  try {
    return Buffer.from(compact, "base64").toString("utf8");
  } catch {
    return undefined;
  }
}

const stripHtml = (s: string): string => s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

/**
 * Burp issue parser for Burp Suite's XML issue export (the documented
 * "export issues" format: <issues><issue>… with base64 request/response
 * under <requestresponse>). XML is read ONLY through the XXE-safe reader
 * in import-security.ts (§61). Base64 evidence is decoded, then passed
 * through the same redaction pipeline as every other evidence source —
 * Burp exports routinely contain live session cookies (§11/§27).
 */
export class BurpIssueParser {
  readonly tool = "burp-suite-professional";

  parse(xml: string): ParsedProxy {
    const out = emptyParsedProxy();
    const doc = parseXmlDocument(xml);
    const issueNodes: XmlNode[] = doc.name === "issues" ? xmlChildren(doc, "issue") : doc.name === "issue" ? [doc] : [];
    out.records = issueNodes.length;
    for (const node of issueNodes.slice(0, MAX_IMPORT_RECORDS)) {
      const name = xmlText(xmlChild(node, "name")) ?? "Burp issue";
      const hostText = xmlText(xmlChild(node, "host"));
      const path = xmlText(xmlChild(node, "path")) ?? xmlText(xmlChild(node, "location")) ?? "/";
      const typeCode = xmlText(xmlChild(node, "type"));
      const severity = mapBurpSeverity(xmlText(xmlChild(node, "severity")));
      const confidence = mapBurpConfidence(xmlText(xmlChild(node, "confidence")));
      const vulnClass = vulnClassForIssueName(name);
      let endpoint: string | undefined;
      let host: string | undefined;
      let port: number | undefined;
      let protocol = "https";
      if (hostText) {
        const base = hostText.includes("://") ? hostText : `https://${hostText}`;
        const hp = hostPortOf(base);
        host = hp.host; port = hp.port; protocol = hp.protocol;
        endpoint = `${base.replace(/\/$/, "")}${path.startsWith("/") ? path : `/${path}`}`;
      }
      const rr = xmlChild(node, "requestresponse");
      const requestRaw = rr ? decodeBase64(xmlText(xmlChild(rr, "request"))) : undefined;
      const responseRaw = rr ? decodeBase64(xmlText(xmlChild(rr, "response"))) : undefined;
      const detail = xmlText(xmlChild(node, "issueDetail"));
      const background = xmlText(xmlChild(node, "issueBackground"));
      const remediationDetail = xmlText(xmlChild(node, "remediationDetail"));
      const remediationBackground = xmlText(xmlChild(node, "remediationBackground"));
      out.findings.push(makeFinding({
        title: name,
        description: stripHtml(detail ?? background ?? name),
        severity,
        vulnClass,
        ...(host ? { host } : {}),
        ...(port !== undefined ? { port } : {}),
        protocol,
        ...(endpoint ? { endpoint } : {}),
        ...(remediationDetail || remediationBackground ? { remediation: stripHtml(remediationDetail ?? remediationBackground!) } : {}),
        sourceTool: this.tool,
        sourceConfidence: confidence.score,
        templateId: typeCode,
        signatureFamily: typeCode ? `burp-issue-type:${typeCode}` : "burp-issue",
        evidenceSummary: `Burp issue "${name}" (${xmlText(xmlChild(node, "severity")) ?? "?"}/${xmlText(xmlChild(node, "confidence")) ?? "?"}) at ${endpoint ?? host ?? "target"}`,
        evidenceDetail: {
          ...(endpoint ? { matchedAt: endpoint } : {}),
          ...(requestRaw ? { request: requestRaw } : {}),
          ...(responseRaw ? { response: responseRaw } : {}),
          ...(typeCode ? { checkId: typeCode } : {}),
          signatureFamily: typeCode ? `burp-issue-type:${typeCode}` : "burp-issue",
          metadata: {
            scannerProduct: "Burp Suite Professional",
            issueType: typeCode ?? name,
            confidenceLabel: confidence.label,
            ...(background ? { scannerNotes: stripHtml(background).slice(0, 500) } : {}),
          },
        },
      }));
      if (endpoint && (requestRaw || responseRaw)) {
        const method = requestRaw?.split(/\s+/)[0] ?? "GET";
        const status = responseRaw ? Number(responseRaw.split(/\s+/)[1]) || undefined : undefined;
        const tx = toTransaction({ method, url: endpoint, statusCode: status, requestRaw, responseRaw, source: this.tool });
        if (tx) out.transactions.push(tx);
      }
      if (endpoint) {
        const ep = endpointFromUrl(endpoint, this.tool);
        if (ep) out.endpoints.push(ep);
      }
    }
    out.metrics = { issues: issueNodes.length, findings: out.findings.length };
    return out;
  }
}

// ------------------------------- Caido (§32) -------------------------------

interface CaidoFindingLike {
  title?: string; name?: string; description?: string; severity?: string;
  host?: string; url?: string; endpoint?: string; parameter?: string; id?: string;
}
interface CaidoRequestLike {
  method?: string; url?: string; host?: string; path?: string; status?: number; statusCode?: number;
  request?: string; response?: string; createdAt?: string; timestamp?: string; durationMs?: number;
  isWebSocket?: boolean; websocket?: boolean;
}

/**
 * Caido parser (§13/§32). Caido's automation surface differs per version,
 * so this parser accepts the tolerant export envelope the connector
 * normalizes vendor responses into ({ findings: [...], requests: [...] },
 * optionally under a GraphQL-style { data: ... } wrapper). Unknown shapes
 * produce warnings, never invented findings (§67).
 */
export class CaidoIssueParser {
  readonly tool = "caido";

  parse(payload: unknown): ParsedProxy {
    const out = emptyParsedProxy();
    let root: Record<string, unknown> = {};
    if (payload && typeof payload === "object") {
      const p = payload as Record<string, unknown>;
      root = (p.data && typeof p.data === "object" ? (p.data as Record<string, unknown>) : p);
    }
    const findings = (Array.isArray(root.findings) ? root.findings : []) as CaidoFindingLike[];
    const requests = (Array.isArray(root.requests) ? root.requests : []) as CaidoRequestLike[];
    out.records = findings.length + requests.length;
    if (!Array.isArray(root.findings) && !Array.isArray(root.requests)) {
      out.warnings.push("Caido payload carried no findings/requests arrays — nothing imported (§67: unrecognized shapes are never guessed into findings)");
    }
    for (const f of findings.slice(0, MAX_IMPORT_RECORDS)) {
      const title = f.title ?? f.name ?? "Caido finding";
      const url = f.url ?? f.endpoint;
      const hp = url ? hostPortOf(url) : (f.host ? { host: f.host, port: undefined, protocol: "https" } : { protocol: "https" });
      out.findings.push(makeFinding({
        title,
        description: f.description ?? title,
        severity: mapCaidoSeverity(f.severity),
        vulnClass: vulnClassForIssueName(title),
        ...(hp.host ? { host: hp.host } : {}),
        ...(hp.port !== undefined ? { port: hp.port } : {}),
        protocol: hp.protocol ?? "https",
        ...(url ? { endpoint: url } : {}),
        ...(f.parameter ? { parameter: f.parameter } : {}),
        sourceTool: this.tool,
        sourceConfidence: 0.6,
        ...(f.id ? { templateId: String(f.id) } : {}),
        signatureFamily: "caido-finding",
        evidenceSummary: `Caido finding "${title}" at ${url ?? hp.host ?? "target"}`,
        evidenceDetail: {
          ...(url ? { matchedAt: url } : {}),
          metadata: { scannerProduct: "Caido", issueType: title, confidenceLabel: "Unspecified" },
        },
      }));
    }
    for (const r of requests.slice(0, MAX_IMPORT_RECORDS)) {
      const url = r.url ?? (r.host ? `https://${r.host}${r.path ?? "/"}` : undefined);
      if (!url) continue;
      if (r.isWebSocket || r.websocket || isWebSocketUrl(url)) {
        out.webSockets.push({ url, source: this.tool });
        continue;
      }
      const tx = toTransaction({
        method: r.method, url, statusCode: r.statusCode ?? r.status,
        timestamp: r.timestamp ?? r.createdAt, durationMs: r.durationMs,
        requestRaw: r.request, responseRaw: r.response, source: this.tool,
      });
      if (tx) out.transactions.push(tx);
      const ep = endpointFromUrl(url, this.tool, r.method, r.statusCode ?? r.status);
      if (ep) out.endpoints.push(ep);
    }
    out.metrics = { findings: out.findings.length, requests: requests.length };
    return out;
  }
}

// ------------------------------- HAR import (§7/§62) -------------------------------

interface HarEntry {
  request?: { method?: string; url?: string; headers?: Array<{ name: string; value: string }>; postData?: { text?: string; mimeType?: string } };
  response?: { status?: number; headers?: Array<{ name: string; value: string }>; content?: { text?: string; mimeType?: string } };
  startedDateTime?: string;
  time?: number;
}

/**
 * HAR (HTTP Archive) import — the manual-testing import path for
 * authorized imported requests (§7). HAR carries traffic, not issues:
 * this importer produces endpoints + transactions ONLY, never findings.
 * Strict validation: a log.entries array is required, entries are capped,
 * and non-http(s) URLs are dropped with a warning.
 */
export class HarImporter {
  readonly tool = "har-import";

  parse(payload: unknown, source = "har-import"): ParsedProxy {
    const out = emptyParsedProxy();
    const log = (payload as { log?: { entries?: unknown } } | null)?.log;
    if (!log || !Array.isArray(log.entries)) {
      out.warnings.push("HAR import rejected: payload has no log.entries array (§62)");
      return out;
    }
    const entries = log.entries as HarEntry[];
    out.records = entries.length;
    let dropped = 0;
    for (const entry of entries.slice(0, MAX_IMPORT_RECORDS)) {
      const url = entry.request?.url;
      if (!url || !/^https?:\/\//i.test(url)) { dropped++; continue; }
      const reqRaw = entry.request
        ? `${entry.request.method ?? "GET"} ${url} HTTP/1.1\n${(entry.request.headers ?? []).map((h) => `${h.name}: ${h.value}`).join("\n")}\n\n${entry.request.postData?.text ?? ""}`
        : undefined;
      const resRaw = entry.response
        ? `HTTP/1.1 ${entry.response.status ?? ""}\n${(entry.response.headers ?? []).map((h) => `${h.name}: ${h.value}`).join("\n")}\n\n${entry.response.content?.text ?? ""}`
        : undefined;
      const tx = toTransaction({
        method: entry.request?.method, url, statusCode: entry.response?.status,
        timestamp: entry.startedDateTime, durationMs: typeof entry.time === "number" ? entry.time : undefined,
        requestRaw: reqRaw, responseRaw: resRaw, source,
      });
      if (tx) out.transactions.push(tx);
      const ep = endpointFromUrl(url, source, entry.request?.method, entry.response?.status);
      if (ep) out.endpoints.push(ep);
      if (isGraphQlEndpoint(url)) out.observations.push({ kind: "INFORMATIONAL", summary: `GraphQL endpoint observed in imported traffic: ${url} (§51)` });
      if (isOpenApiDocumentUrl(url)) out.observations.push({ kind: "INFORMATIONAL", summary: `OpenAPI document observed in imported traffic: ${url} — stored as reference, scope not trusted (§52)` });
    }
    if (dropped > 0) out.warnings.push(`HAR import dropped ${dropped} entries with non-http(s) or missing URLs (§62)`);
    out.metrics = { transactions: out.transactions.length, endpoints: out.endpoints.length, apiEndpoints: out.endpoints.filter((e) => classifyApiKind(e.url, e.contentType) !== "WEB").length };
    return out;
  }
}

// ------------------------------- mitmproxy flows (Prompt 9 §33) -------------------------------

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

interface MitmHeader { name: string; value: string }
function mitmHeaders(raw: unknown): MitmHeader[] {
  if (!Array.isArray(raw)) return [];
  const out: MitmHeader[] = [];
  for (const pair of raw) {
    if (Array.isArray(pair) && typeof pair[0] === "string") out.push({ name: pair[0], value: typeof pair[1] === "string" ? pair[1] : "" });
    else if (isRecord(pair) && typeof pair.name === "string") out.push({ name: pair.name, value: typeof pair.value === "string" ? pair.value : "" });
  }
  return out;
}
function headerValue(headers: MitmHeader[], name: string): string | undefined {
  return headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value;
}

/**
 * mitmproxy flow dump / mitmweb /flows parser (Prompt 9 §33/§34):
 * traffic becomes normalized transactions (redacted display copies +
 * hashes — raw bytes never persist), API endpoint inventory and
 * WebSocket inventory including whether the handshake carried
 * authentication material (presence only, §32). mitmproxy produces
 * OBSERVATIONS and inventory — never vulnerability findings.
 */
export class MitmproxyFlowParser {
  parse(raw: unknown, source: string): ParsedProxy {
    const out = emptyParsedProxy();
    const flows = Array.isArray(raw) ? raw : isRecord(raw) && Array.isArray((raw as Record<string, unknown>).flows) ? ((raw as Record<string, unknown>).flows as unknown[]) : null;
    if (!flows) {
      out.warnings.push("mitmproxy payload did not contain a flow list — nothing imported");
      return out;
    }
    let dropped = 0;
    for (const flow of flows.slice(0, MAX_IMPORT_RECORDS)) {
      if (!isRecord(flow) || !isRecord(flow.request)) { dropped++; continue; }
      const req = flow.request;
      const method = typeof req.method === "string" ? req.method.toUpperCase() : "GET";
      const scheme = typeof req.scheme === "string" ? req.scheme : "https";
      const host = typeof req.host === "string" ? req.host : "";
      const port = typeof req.port === "number" ? req.port : undefined;
      const path = typeof req.path === "string" ? req.path : "/";
      if (!host) { dropped++; continue; }
      const defaultPort = scheme === "https" || scheme === "wss" ? 443 : 80;
      const portPart = port !== undefined && port !== defaultPort ? `:${port}` : "";
      const url = `${scheme}://${host}${portPart}${path}`;
      const reqHeaders = mitmHeaders(req.headers);
      const res = isRecord(flow.response) ? flow.response : undefined;
      const resHeaders = res ? mitmHeaders(res.headers) : [];
      const statusCode = res && typeof res.status_code === "number" ? res.status_code : undefined;
      const isWebSocket = scheme === "ws" || scheme === "wss"
        || (headerValue(reqHeaders, "upgrade") ?? "").toLowerCase() === "websocket"
        || flow.websocket !== undefined;
      if (isWebSocket) {
        // §32: inventory only — messages are never inspected for attacks.
        out.webSockets.push({
          url: url.replace(/^http/, "ws"),
          ...(headerValue(reqHeaders, "origin") ? { origin: headerValue(reqHeaders, "origin") } : {}),
          ...(headerValue(reqHeaders, "sec-websocket-protocol") ? { subprotocol: headerValue(reqHeaders, "sec-websocket-protocol") } : {}),
          source,
          authPresent: !!(headerValue(reqHeaders, "authorization") || headerValue(reqHeaders, "cookie")),
        });
        continue;
      }
      const reqRaw = `${method} ${path} HTTP/1.1\n${reqHeaders.map((h) => `${h.name}: ${h.value}`).join("\n")}\n\n${typeof req.content === "string" ? req.content : ""}`;
      const resRaw = res ? `HTTP/1.1 ${statusCode ?? ""}\n${resHeaders.map((h) => `${h.name}: ${h.value}`).join("\n")}\n\n${typeof res.content === "string" ? res.content : ""}` : undefined;
      const tx = toTransaction({ method, url, statusCode, requestRaw: reqRaw, responseRaw: resRaw, source });
      if (tx) out.transactions.push(tx);
      const ep = endpointFromUrl(url, source, method, statusCode);
      if (ep) {
        if (classifyApiKind(ep.url, headerValue(resHeaders, "content-type")) !== "WEB") ep.endpointType = "API";
        out.endpoints.push(ep);
      }
    }
    if (dropped > 0) out.warnings.push(`mitmproxy import dropped ${dropped} malformed flow record(s)`);
    out.records = out.transactions.length + out.webSockets.length;
    out.metrics = {
      transactions: out.transactions.length, endpoints: out.endpoints.length, webSockets: out.webSockets.length,
      apiEndpoints: out.endpoints.filter((e) => e.endpointType === "API").length,
    };
    return out;
  }
}
