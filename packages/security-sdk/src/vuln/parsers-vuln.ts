import type { Severity } from "@zerosweep/types";
import type { NormalizedService } from "../findings/finding.types";
import { canonicalizeHostname } from "../recon/normalize";
import { parseJsonLines, str, strArr } from "../recon/parsers-common";
import { sourceFindingFingerprint } from "./analysis";
import { prepareEvidence, sanitizeReferenceUrl } from "./redact";
import { taxonomyFor } from "./taxonomy";
// (taxonomyFor also supplies curated titles for TLS findings.)
import { templateMeta } from "./template-policy";
import type { NormalizedReference, NormalizedVulnFinding } from "./types";

/**
 * Vulnerability parsers (Prompt 7 §15). Same discipline as the recon
 * parsers: malformed records become warnings, never exceptions; partial
 * output survives. Parsers also SANITIZE: evidence is redacted + capped
 * here (§30/§31), reference URLs are validated (§54), and CVE/CWE/CVSS are
 * carried ONLY when the tool output itself provides them (§17/§26/§27) —
 * CWE/OWASP otherwise come from the curated class taxonomy.
 */

export interface ParsedObservation {
  kind: "TECHNOLOGY" | "CONFIGURATION" | "INFORMATIONAL";
  summary: string;
  host?: string;
}

export interface ParsedVuln {
  findings: NormalizedVulnFinding[];
  /** Non-finding output: technology metadata, configuration observations,
   *  informational messages (§10) — tracked, never promoted silently. */
  observations: ParsedObservation[];
  services: NormalizedService[];
  /** Recon-shape fields, always empty here: vuln parsers report services +
   *  findings, never asset/endpoint inventory (kept so a VulnParser also
   *  satisfies the ReconParser contract of the shared adapter base). */
  assets: [];
  endpoints: [];
  technologies: [];
  records: number;
  warnings: string[];
  metrics: Record<string, number>;
}

export interface VulnParser {
  readonly tool: string;
  parse(raw: string): ParsedVuln;
}

export const EVIDENCE_CAP_BYTES = 256 * 1024;

function emptyParsed(): ParsedVuln {
  return { findings: [], observations: [], services: [], assets: [], endpoints: [], technologies: [], records: 0, warnings: [], metrics: {} };
}

const SEVERITY_MAP: Record<string, Severity> = {
  critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", moderate: "MEDIUM",
  low: "LOW", info: "INFORMATIONAL", informational: "INFORMATIONAL", none: "INFORMATIONAL",
  warn: "LOW", warning: "LOW", ok: "INFORMATIONAL",
};

export function mapScannerSeverity(raw: unknown, fallback: Severity = "INFORMATIONAL"): Severity {
  if (typeof raw !== "string") return fallback;
  return SEVERITY_MAP[raw.trim().toLowerCase()] ?? fallback;
}

export function normCwe(raw: unknown): string | undefined {
  if (typeof raw === "number" && Number.isFinite(raw)) return `CWE-${raw}`;
  if (typeof raw !== "string") return undefined;
  const m = raw.match(/(?:cwe-)?(\d{1,5})/i);
  return m ? `CWE-${m[1]}` : undefined;
}

export function normCve(raw: unknown): string | undefined {
  const first = Array.isArray(raw) ? raw.find((x) => typeof x === "string") : raw;
  if (typeof first !== "string") return undefined;
  const m = first.match(/CVE-\d{4}-\d{4,7}/i);
  return m ? m[0].toUpperCase() : undefined;
}

export function normCvss(raw: unknown): number | undefined {
  const n = typeof raw === "string" ? Number(raw) : raw;
  return typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 10 ? n : undefined;
}

export function buildReferences(input: { urls?: unknown; cve?: string; cwe?: string }): NormalizedReference[] {
  const refs: NormalizedReference[] = [];
  const seen = new Set<string>();
  for (const u of Array.isArray(input.urls) ? input.urls : []) {
    const url = sanitizeReferenceUrl(u);
    if (url && !seen.has(url)) { seen.add(url); refs.push({ type: "URL", label: "Scanner reference", url }); }
  }
  if (input.cve) refs.push({ type: "CVE", label: input.cve, url: `https://nvd.nist.gov/vuln/detail/${input.cve}` });
  if (input.cwe) refs.push({ type: "CWE", label: input.cwe, url: `https://cwe.mitre.org/data/definitions/${input.cwe.replace("CWE-", "")}.html` });
  return refs;
}

interface FindingDraft {
  title: string; description: string; severity: Severity; vulnClass: string;
  host?: string; port?: number; protocol?: string; endpoint?: string; parameter?: string;
  cve?: string; cwe?: string; cvssScore?: number; cvssVector?: string; cvssVersion?: string;
  remediation?: string; referenceUrls?: unknown; sourceTool: string; sourceConfidence: number;
  templateId?: string; signatureFamily?: string;
  evidenceSummary: string;
  evidenceDetail?: NormalizedVulnFinding["evidenceDetail"];
}

/** Assemble a normalized finding from a parser draft: taxonomy fills
 *  CWE/OWASP/remediation/impact ONLY from the curated class mapping;
 *  source-provided values always win. Fingerprint is the per-source one. */
export function makeFinding(draft: FindingDraft): NormalizedVulnFinding {
  const tax = taxonomyFor(draft.vulnClass);
  const cwe = draft.cwe ?? tax.cwe;
  const refs = buildReferences({ urls: draft.referenceUrls, cve: draft.cve, cwe });
  const detail = draft.evidenceDetail
    ? {
        ...draft.evidenceDetail,
        ...(draft.evidenceDetail.request !== undefined ? { request: prepareEvidence(draft.evidenceDetail.request, EVIDENCE_CAP_BYTES).text } : {}),
        ...(draft.evidenceDetail.response !== undefined ? { response: prepareEvidence(draft.evidenceDetail.response, EVIDENCE_CAP_BYTES).text } : {}),
      }
    : undefined;
  const fpInput = {
    host: draft.host ?? "", port: draft.port, endpoint: draft.endpoint, parameter: draft.parameter,
    vulnClass: draft.vulnClass, cve: draft.cve, cwe, sourceTool: draft.sourceTool, checkId: draft.templateId,
  };
  return {
    title: draft.title,
    description: draft.description,
    severity: draft.severity,
    confidence: draft.sourceConfidence,
    ...(draft.host ? { host: draft.host } : {}),
    ...(draft.port !== undefined ? { port: draft.port } : {}),
    ...(draft.protocol ? { protocol: draft.protocol } : {}),
    ...(draft.endpoint ? { endpoint: draft.endpoint } : {}),
    ...(draft.parameter ? { parameter: draft.parameter } : {}),
    ...(draft.cve ? { cve: draft.cve } : {}),
    ...(cwe ? { cwe } : {}),
    ...(draft.cvssScore !== undefined ? { cvssScore: draft.cvssScore } : {}),
    ...(draft.cvssVector ? { cvssVector: draft.cvssVector } : {}),
    ...(draft.cvssVersion ? { cvssVersion: draft.cvssVersion } : {}),
    ...(tax.owaspCategory ? { owaspCategory: tax.owaspCategory } : {}),
    ...(tax.technicalImpact ? { technicalImpact: tax.technicalImpact } : {}),
    evidence: draft.evidenceSummary,
    remediation: draft.remediation ?? tax.remediation ?? "",
    references: refs.map((r) => r.url),
    referencesDetailed: refs,
    sourceTool: draft.sourceTool,
    sourceFingerprint: sourceFindingFingerprint(fpInput),
    vulnClass: draft.vulnClass,
    sourceConfidence: draft.sourceConfidence,
    ...(draft.templateId ? { templateId: draft.templateId } : {}),
    ...(draft.signatureFamily ? { signatureFamily: draft.signatureFamily } : {}),
    ...(detail ? { evidenceDetail: detail } : {}),
    verificationStatus: "UNVERIFIED",
  };
}

// ------------------------------- Nuclei (§15) -------------------------------

export class NucleiParser implements VulnParser {
  readonly tool = "nuclei";
  parse(raw: string): ParsedVuln {
    const out = emptyParsed();
    const { records, warnings } = parseJsonLines(raw, this.tool);
    out.warnings.push(...warnings);
    out.records = records.length;
    for (const rec of records) {
      const info = (rec.info ?? {}) as Record<string, unknown>;
      const classification = (info.classification ?? {}) as Record<string, unknown>;
      const templateId = str(rec["template-id"]) ?? "unknown-template";
      const catalog = templateMeta(templateId);
      const matchedAt = str(rec["matched-at"]);
      const hostRaw = str(rec.host) ?? (matchedAt ? matchedAt.split(":")[0] : undefined);
      const host = hostRaw ? canonicalizeHostname(hostRaw) ?? hostRaw.toLowerCase() : undefined;
      const isUrl = matchedAt?.startsWith("http");
      const port = typeof rec.port === "number" ? rec.port : isUrl ? undefined : matchedAt?.includes(":") ? Number(matchedAt.split(":").pop()) || undefined : undefined;
      const cve = normCve(classification["cve-id"]) ?? catalog?.cve;
      const cwe = normCwe(classification["cwe-id"]) ?? catalog?.cwe;
      const finding = makeFinding({
        title: str(info.name) ?? catalog?.name ?? templateId,
        description: str(info.description) ?? `Nuclei template ${templateId} matched.`,
        severity: mapScannerSeverity(info.severity, catalog?.severity ?? "INFORMATIONAL"),
        vulnClass: catalog?.vulnClass ?? "GENERIC_VULNERABILITY",
        ...(host ? { host } : {}),
        ...(port !== undefined ? { port } : {}),
        protocol: str(rec.type) === "ssl" ? "tls" : "https",
        ...(isUrl && matchedAt ? { endpoint: matchedAt } : {}),
        ...(cve ? { cve } : {}),
        ...(cwe ? { cwe } : {}),
        ...(normCvss(classification["cvss-score"]) ?? catalog?.cvssScore ? { cvssScore: normCvss(classification["cvss-score"]) ?? catalog?.cvssScore } : {}),
        ...(str(classification["cvss-metrics"]) ?? catalog?.cvssVector ? { cvssVector: str(classification["cvss-metrics"]) ?? catalog?.cvssVector } : {}),
        referenceUrls: info.reference,
        sourceTool: this.tool,
        sourceConfidence: 0.75,
        templateId,
        signatureFamily: `nuclei-template:${templateId}`,
        evidenceSummary: `Template ${templateId} matched at ${matchedAt ?? host ?? "target"}`,
        evidenceDetail: {
          ...(matchedAt ? { matchedAt } : {}),
          ...(str(rec.request) ? { request: str(rec.request) } : {}),
          ...(str(rec.response) ? { response: str(rec.response) } : {}),
          checkId: templateId,
          signatureFamily: `nuclei-template:${templateId}`,
          metadata: { templateId, ...(catalog ? { classification: catalog.classification } : { classification: "REVIEW_REQUIRED (uncurated)" }) },
        },
      });
      out.findings.push(finding);
    }
    out.metrics = { records: out.records, findings: out.findings.length };
    return out;
  }
}

// ------------------------------- Nikto (§10/§15) -------------------------------

interface NiktoRule { match: RegExp; vulnClass: string; severity: Severity; confidence: number }
const NIKTO_RULES: NiktoRule[] = [
  { match: /x-frame-options|anti-clickjacking/i, vulnClass: "MISSING_SECURITY_HEADERS", severity: "LOW", confidence: 0.7 },
  { match: /header is not present|header is not set|missing.*header/i, vulnClass: "MISSING_SECURITY_HEADERS", severity: "LOW", confidence: 0.65 },
  { match: /directory indexing|directory listing/i, vulnClass: "DIRECTORY_LISTING", severity: "MEDIUM", confidence: 0.75 },
  { match: /appears to be outdated|is outdated/i, vulnClass: "OUTDATED_SOFTWARE", severity: "LOW", confidence: 0.55 },
  { match: /allowed http methods|trace method/i, vulnClass: "SERVER_MISCONFIGURATION", severity: "LOW", confidence: 0.65 },
  { match: /\.git|\.env|config file|configuration file/i, vulnClass: "EXPOSED_FILE", severity: "MEDIUM", confidence: 0.7 },
  { match: /etag|inode/i, vulnClass: "INFORMATION_DISCLOSURE", severity: "LOW", confidence: 0.6 },
];
const NIKTO_INFORMATIONAL = /interesting|banner|uncommon header|retrieved/i;

export class NiktoParser implements VulnParser {
  readonly tool = "nikto";
  parse(raw: string): ParsedVuln {
    const out = emptyParsed();
    let doc: Record<string, unknown> | undefined;
    try { doc = JSON.parse(raw) as Record<string, unknown>; } catch { /* handled below */ }
    if (!doc || typeof doc !== "object") {
      // Plain-text fallback: "+ <message>" lines (nikto's default output).
      for (const line of raw.split(/\r?\n/)) {
        const m = line.match(/^\+\s+(.*)$/);
        if (m) this.classify(m[1]!, undefined, undefined, out);
      }
      out.records = out.findings.length + out.observations.length;
      out.metrics = { records: out.records, findings: out.findings.length, observations: out.observations.length };
      return out;
    }
    const host = str(doc.host) ? canonicalizeHostname(str(doc.host)!) ?? str(doc.host)!.toLowerCase() : undefined;
    const port = typeof doc.port === "number" ? doc.port : undefined;
    const scheme = port === 443 ? "https" : "http";
    if (str(doc.banner) && host) {
      out.observations.push({ kind: "TECHNOLOGY", summary: `Server banner: ${str(doc.banner)}`, host });
    }
    const vulns = Array.isArray(doc.vulnerabilities) ? doc.vulnerabilities : [];
    for (const v of vulns as Record<string, unknown>[]) {
      const msg = str(v.msg) ?? "";
      const urlPath = str(v.url) ?? "/";
      const endpoint = host ? `${scheme}://${host}${urlPath.startsWith("/") ? urlPath : `/${urlPath}`}` : undefined;
      this.classify(msg, host, endpoint, out, { id: str(v.id), osvdb: str(v.OSVDB) }, port);
    }
    out.records = vulns.length;
    out.metrics = { records: out.records, findings: out.findings.length, observations: out.observations.length };
    return out;
  }

  private classify(msg: string, host: string | undefined, endpoint: string | undefined, out: ParsedVuln, ids: { id?: string; osvdb?: string } = {}, port?: number): void {
    if (!msg) return;
    const rule = NIKTO_RULES.find((r) => r.match.test(msg));
    if (!rule) {
      // §10: informational Nikto messages are observations/findings of
      // INFORMATIONAL class only — never silently promoted.
      if (NIKTO_INFORMATIONAL.test(msg)) {
        out.observations.push({ kind: "INFORMATIONAL", summary: msg, ...(host ? { host } : {}) });
        return;
      }
      out.findings.push(makeFinding({
        title: "Nikto Observation Requiring Review",
        description: msg, severity: "INFORMATIONAL", vulnClass: "GENERIC_VULNERABILITY",
        ...(host ? { host } : {}), ...(port !== undefined ? { port } : {}), ...(endpoint ? { endpoint } : {}),
        sourceTool: this.tool, sourceConfidence: 0.4, signatureFamily: "nikto-heuristics",
        evidenceSummary: msg,
        evidenceDetail: { ...(endpoint ? { matchedAt: endpoint } : {}), ...(ids.id ? { checkId: ids.id } : {}), signatureFamily: "nikto-heuristics", metadata: { ...(ids.id ? { niktoId: ids.id } : {}), ...(ids.osvdb && ids.osvdb !== "0" ? { osvdb: ids.osvdb } : {}) } },
      }));
      return;
    }
    out.findings.push(makeFinding({
      title: msg.length > 140 ? `${msg.slice(0, 137)}…` : msg,
      description: msg, severity: rule.severity, vulnClass: rule.vulnClass,
      ...(host ? { host } : {}), ...(port !== undefined ? { port } : {}), ...(endpoint ? { endpoint } : {}),
      sourceTool: this.tool, sourceConfidence: rule.confidence, signatureFamily: "nikto-heuristics",
      evidenceSummary: msg,
      evidenceDetail: { ...(endpoint ? { matchedAt: endpoint } : {}), ...(ids.id ? { checkId: ids.id } : {}), signatureFamily: "nikto-heuristics", metadata: { ...(ids.id ? { niktoId: ids.id } : {}), ...(ids.osvdb && ids.osvdb !== "0" ? { osvdb: ids.osvdb } : {}) } },
    }));
  }
}

// ------------------------------- testssl.sh (§15) -------------------------------

export class TestsslParser implements VulnParser {
  readonly tool = "testssl";
  parse(raw: string): ParsedVuln {
    const out = emptyParsed();
    let entries: Record<string, unknown>[] = [];
    try {
      const doc = JSON.parse(raw) as unknown;
      entries = Array.isArray(doc) ? (doc as Record<string, unknown>[]) : [];
      if (entries.length === 0 && doc && typeof doc === "object") out.warnings.push("testssl: output was not a JSON array — no entries parsed");
    } catch {
      out.warnings.push("testssl: output was not valid JSON — no entries parsed");
      return out;
    }
    for (const e of entries) {
      const id = str(e.id) ?? "";
      const findingText = str(e.finding) ?? "";
      const sevRaw = (str(e.severity) ?? "").toUpperCase();
      const ipField = str(e.ip) ?? "";
      const host = canonicalizeHostname(ipField.split("/")[0] ?? "") ?? undefined;
      const port = Number(str(e.port)) || 443;
      const base = { host, port };
      if (sevRaw === "OK" || sevRaw === "INFO") {
        out.observations.push({ kind: "CONFIGURATION", summary: `testssl ${id}: ${findingText}`, ...(host ? { host } : {}) });
        out.records++;
        continue;
      }
      out.records++;
      let vulnClass = "TLS_CONFIGURATION";
      if (/^(SSLv2|SSLv3|TLS1|TLS1_1|TLS1_2|TLS1_3)/i.test(id) || /protocol/i.test(id)) vulnClass = "TLS_WEAK_PROTOCOL";
      else if (/cipher/i.test(id)) vulnClass = "TLS_WEAK_CIPHER";
      else if (/cert_expiration|expired/i.test(`${id} ${findingText}`)) vulnClass = "TLS_CERTIFICATE_EXPIRED";
      else if (/cert_|chain|trust/i.test(id)) vulnClass = "TLS_CERTIFICATE_UNTRUSTED";
      else if (/HSTS|header/i.test(id)) vulnClass = "MISSING_SECURITY_HEADERS";
      else if (/heartbleed|ticketbleed|robot|ccs|renegotiation|crime|breach|lucky13|beast|poodle|sweet32/i.test(id)) vulnClass = "GENERIC_VULNERABILITY";
      const cve = normCve(e.cve);
      out.findings.push(makeFinding({
        title: `${taxonomyFor(vulnClass).title} — testssl ${id}`,
        description: `testssl.sh check ${id}: ${findingText}`,
        severity: mapScannerSeverity(sevRaw, "LOW"),
        vulnClass,
        ...(host ? { host } : {}), port, protocol: "tls",
        ...(cve ? { cve } : {}),
        ...(normCwe(e.cwe) ? { cwe: normCwe(e.cwe) } : {}),
        sourceTool: this.tool, sourceConfidence: 0.85, signatureFamily: `testssl-check:${id}`,
        evidenceSummary: `testssl ${id}: ${findingText}`,
        evidenceDetail: { ...(host ? { matchedAt: `${host}:${port}` } : {}), checkId: id, signatureFamily: `testssl-check:${id}`, metadata: { check: id, severity: sevRaw } },
      }));
      void base;
    }
    out.services = tlsServices(out.findings, out.observations);
    out.metrics = { records: out.records, findings: out.findings.length, observations: out.observations.length };
    return out;
  }
}

function tlsServices(findings: NormalizedVulnFinding[], _obs: ParsedObservation[]): NormalizedService[] {
  const seen = new Map<string, NormalizedService>();
  for (const f of findings) {
    if (!f.host || f.port === undefined) continue;
    const key = `${f.host}|${f.port}`;
    if (!seen.has(key)) seen.set(key, { host: f.host, port: f.port, protocol: "tcp", name: "https", scheme: "https" });
  }
  return [...seen.values()];
}

// ------------------------------- SSLyze (§15) -------------------------------

const SSLYZE_PROTOCOLS: { key: string; label: string; severity: Severity }[] = [
  { key: "ssl_2_0_cipher_suites", label: "SSL 2.0", severity: "HIGH" },
  { key: "ssl_3_0_cipher_suites", label: "SSL 3.0", severity: "HIGH" },
  { key: "tls_1_0_cipher_suites", label: "TLS 1.0", severity: "MEDIUM" },
  { key: "tls_1_1_cipher_suites", label: "TLS 1.1", severity: "MEDIUM" },
];

function dig(obj: unknown, ...path: string[]): unknown {
  let cur: unknown = obj;
  for (const p of path) {
    if (!cur || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

export class SslyzeParser implements VulnParser {
  readonly tool = "sslyze";
  parse(raw: string): ParsedVuln {
    const out = emptyParsed();
    let doc: Record<string, unknown>;
    try { doc = JSON.parse(raw) as Record<string, unknown>; } catch {
      out.warnings.push("sslyze: output was not valid JSON — no results parsed");
      return out;
    }
    const results = Array.isArray(doc.server_scan_results) ? (doc.server_scan_results as Record<string, unknown>[]) : [];
    if (results.length === 0) out.warnings.push("sslyze: no server_scan_results in output");
    for (const res of results) {
      const loc = (res.server_location ?? {}) as Record<string, unknown>;
      const host = str(loc.hostname) ? canonicalizeHostname(str(loc.hostname)!) ?? str(loc.hostname)!.toLowerCase() : undefined;
      const port = typeof loc.port === "number" ? loc.port : 443;
      const scan = (res.scan_result ?? {}) as Record<string, unknown>;
      out.records++;
      for (const proto of SSLYZE_PROTOCOLS) {
        const suites = dig(scan, proto.key, "result", "accepted_cipher_suites");
        if (Array.isArray(suites) && suites.length > 0) {
          out.findings.push(makeFinding({
            title: `Weak TLS Protocol Supported — ${proto.label}`,
            description: `SSLyze: the server accepts cipher suites over ${proto.label} (${suites.length} suite(s) accepted).`,
            severity: proto.severity, vulnClass: "TLS_WEAK_PROTOCOL",
            ...(host ? { host } : {}), port, protocol: "tls",
            sourceTool: this.tool, sourceConfidence: 0.85, signatureFamily: `sslyze-protocol:${proto.key}`,
            evidenceSummary: `SSLyze: ${proto.label} accepted with ${suites.length} cipher suite(s)`,
            evidenceDetail: { ...(host ? { matchedAt: `${host}:${port}` } : {}), checkId: proto.key, signatureFamily: `sslyze-protocol:${proto.key}`, metadata: { protocol: proto.label, acceptedSuites: String(suites.length) } },
          }));
        }
      }
      // Certificate analysis (§12).
      const deployments = dig(scan, "certificate_info", "result", "certificate_deployments");
      if (Array.isArray(deployments)) {
        for (const dep of deployments as Record<string, unknown>[]) {
          const chain = dig(dep, "received_certificate_chain");
          const leaf = Array.isArray(chain) ? (chain[0] as Record<string, unknown>) : undefined;
          const notAfter = leaf ? str(leaf.not_after) : undefined;
          if (notAfter && new Date(notAfter).getTime() < Date.now()) {
            out.findings.push(makeFinding({
              title: "Expired TLS Certificate",
              description: `SSLyze: the received certificate expired at ${notAfter}.`,
              severity: "HIGH", vulnClass: "TLS_CERTIFICATE_EXPIRED",
              ...(host ? { host } : {}), port, protocol: "tls",
              sourceTool: this.tool, sourceConfidence: 0.9, signatureFamily: "sslyze-certinfo",
              evidenceSummary: `SSLyze: certificate not_after ${notAfter} is in the past`,
              evidenceDetail: { ...(host ? { matchedAt: `${host}:${port}` } : {}), checkId: "certificate_info", signatureFamily: "sslyze-certinfo", metadata: { notAfter } },
            }));
          }
          const validations = dig(dep, "path_validation_results");
          if (Array.isArray(validations) && validations.some((v) => str((v as Record<string, unknown>).result) && str((v as Record<string, unknown>).result) !== "SUCCESS")) {
            out.findings.push(makeFinding({
              title: "TLS Certificate Chain Not Trusted",
              description: "SSLyze: certificate path validation did not succeed against a checked trust store.",
              severity: "MEDIUM", vulnClass: "TLS_CERTIFICATE_UNTRUSTED",
              ...(host ? { host } : {}), port, protocol: "tls",
              sourceTool: this.tool, sourceConfidence: 0.8, signatureFamily: "sslyze-certinfo",
              evidenceSummary: "SSLyze: path validation result was not SUCCESS",
              evidenceDetail: { ...(host ? { matchedAt: `${host}:${port}` } : {}), checkId: "certificate_info", signatureFamily: "sslyze-certinfo" },
            }));
          }
        }
      }
      if (dig(scan, "heartbleed", "result", "is_vulnerable_to_heartbleed") === true) {
        out.findings.push(makeFinding({
          title: "Heartbleed Vulnerability Reported",
          description: "SSLyze: the server is vulnerable to Heartbleed (CVE-2014-0160).",
          severity: "CRITICAL", vulnClass: "GENERIC_VULNERABILITY",
          ...(host ? { host } : {}), port, protocol: "tls", cve: "CVE-2014-0160",
          sourceTool: this.tool, sourceConfidence: 0.9, signatureFamily: "sslyze-heartbleed",
          evidenceSummary: "SSLyze: is_vulnerable_to_heartbleed = true",
          evidenceDetail: { ...(host ? { matchedAt: `${host}:${port}` } : {}), checkId: "heartbleed", signatureFamily: "sslyze-heartbleed" },
        }));
      }
      if (host) out.services.push({ host, port, protocol: "tcp", name: "https", scheme: "https" });
    }
    out.metrics = { records: out.records, findings: out.findings.length, observations: out.observations.length };
    return out;
  }
}
