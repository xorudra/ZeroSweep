import type { ApiFindingDraft, ParsedApi } from "../api/api-adapter.base";
import { emptyParsedApi } from "../api/parsers-api";
import { redactEvidenceText } from "../vuln/redact";
import { sourceFindingFingerprint } from "../vuln/analysis";
import { taxonomyFor } from "../vuln/taxonomy";

/**
 * Structured parsers for the Prompt 32 injection/XSS/WordPress tools
 * (§142). Tool output is UNTRUSTED: malformed records become warnings,
 * never throws, and a parser failure yields an empty result that the
 * pipeline marks partial/error — never a clean scan (§145/§188).
 * Evidence passes through the platform redactor (§114) and payloads
 * are recorded as SAFE MARKERS only (§71) — reflected attack strings
 * from the target are evidence of the check, truncated and redacted.
 */

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function hostOf(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}
function portOf(url: string): number | undefined {
  try { const p = new URL(url).port; return p ? Number(p) : undefined; } catch { return undefined; }
}
function truncate(text: string, max = 400): string {
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function draft(partial: Partial<ApiFindingDraft> & Pick<ApiFindingDraft, "title" | "description" | "severity" | "confidence" | "vulnClass" | "sourceTool" | "sourceFingerprint">): ApiFindingDraft {
  const info = taxonomyFor(partial.vulnClass);
  return {
    references: [],
    cwe: info.cwe,
    owaspCategory: info.owaspCategory,
    remediation: info.remediation,
    ...partial,
  };
}

function xssDraft(source: string, url: string, parameter: string | undefined, evidence: string, verified: boolean): ApiFindingDraft {
  const vulnClass = "XSS_REFLECTED";
  return draft({
    title: verified ? "Reflected Cross-Site Scripting (safe-marker verified)" : "Possible Reflected Cross-Site Scripting",
    description: `${source} reported an XSS reflection context${parameter ? ` in parameter '${parameter}'` : ""} at ${url}. The platform proof uses a harmless marker only (§71); no persistent payload was stored.`,
    severity: verified ? "HIGH" : "MEDIUM",
    confidence: verified ? 0.9 : 0.55,
    vulnClass,
    host: hostOf(url),
    ...(portOf(url) ? { port: portOf(url) } : {}),
    protocol: url.startsWith("http:") ? "http" : "https",
    endpoint: url,
    ...(parameter ? { parameter } : {}),
    evidence: truncate(redactEvidenceText(evidence)),
    sourceTool: source,
    sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host: hostOf(url), endpoint: url, parameter, vulnClass }),
  });
}

/* ------------------------------- Dalfox (§70) ------------------------------- */

/** Dalfox JSON output: an array of result objects with type/param/poc/evidence. */
export function parseDalfoxOutput(text: string, source = "dalfox"): ParsedApi {
  const out = emptyParsedApi();
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { out.warnings.push("dalfox: output is not valid JSON — treated as parser failure, not a clean result (§188)"); return out; }
  const records = Array.isArray(parsed) ? parsed : isRecord(parsed) && Array.isArray(parsed.results) ? parsed.results : null;
  if (!records) { out.warnings.push("dalfox: unexpected output shape — no result array"); return out; }
  let findings = 0;
  for (const rec of records) {
    if (!isRecord(rec)) continue;
    const url = str(rec.url) ?? str(rec.poc) ?? "";
    const param = str(rec.param) ?? str(rec.parameter);
    const type = (str(rec.type) ?? "").toUpperCase();
    const evidence = str(rec.evidence) ?? str(rec.poc) ?? "dalfox marker reflection";
    // Dalfox "V" = verified reflection of the safe marker; "R" = reflected candidate.
    out.findings.push(xssDraft(source, url, param, evidence, type.startsWith("V")));
    findings++;
  }
  out.metrics = { findings };
  return out;
}

/* ------------------------------- XSStrike (§70) ------------------------------- */

/** XSStrike console output: structured marker lines in its log format. */
export function parseXsstrikeOutput(text: string, source = "xsstrike"): ParsedApi {
  const out = emptyParsedApi();
  let findings = 0;
  let currentParam: string | undefined;
  let currentUrl = "";
  for (const line of text.split(/\r?\n/)) {
    const paramMatch = line.match(/parameter[:\s]+['"]?([A-Za-z0-9_[\]-]+)['"]?/i);
    if (/checking/i.test(line) && paramMatch) currentParam = paramMatch[1];
    const urlMatch = line.match(/https?:\/\/[^\s'"]+/);
    if (urlMatch) currentUrl = urlMatch[0];
    if (/reflection found|vulnerable|xss detected/i.test(line) && !/not vulnerable|no reflection/i.test(line)) {
      out.findings.push(xssDraft(source, currentUrl, currentParam, line.trim(), /verified|confirmed/i.test(line)));
      findings++;
    }
  }
  if (findings === 0 && text.trim().length > 0 && !/completed|scan finished/i.test(text)) {
    out.warnings.push("xsstrike: no recognizable result markers — output treated as partial (§188)");
  }
  out.metrics = { findings };
  return out;
}

/* ------------------------------- SQLmap (§73–§76) ------------------------------- */

export interface SqlmapParseResult extends ParsedApi {
  dbmsHint?: string;
  techniques: string[];
}

/** SQLmap console output: parameter blocks with Type/Title/Payload and the DBMS line. */
export function parseSqlmapOutput(text: string, source = "sqlmap"): SqlmapParseResult {
  const out: SqlmapParseResult = { ...emptyParsedApi(), techniques: [] };
  const dbms = text.match(/back-end DBMS is ([^\r\n]+)/i);
  if (dbms) out.dbmsHint = dbms[1]!.trim();
  const blocks = text.split(/Parameter:\s+/).slice(1);
  let findings = 0;
  for (const block of blocks) {
    const head = block.split(/\r?\n/)[0] ?? "";
    const paramMatch = head.match(/^([^\s(]+)/);
    const parameter = paramMatch ? paramMatch[1] : undefined;
    const types = [...block.matchAll(/Type:\s*([^\r\n]+)/g)].map((m) => m[1]!.trim());
    for (const t of types) if (!out.techniques.includes(t)) out.techniques.push(t);
    const title = block.match(/Title:\s*([^\r\n]+)/)?.[1]?.trim();
    const urlMatch = block.match(/https?:\/\/[^\s'"]+/);
    const url = urlMatch ? urlMatch[0] : "";
    if (types.length === 0) continue;
    const vulnClass = "SQL_INJECTION";
    out.findings.push(draft({
      title: "SQL Injection (detection-only confirmation)",
      description: `sqlmap confirmed an injectable parameter using detection techniques only (${types.join(", ")}). Data extraction, file access and OS interaction are disabled by platform policy (§74) — no data was read or modified.`,
      severity: "HIGH",
      confidence: 0.9,
      vulnClass,
      host: hostOf(url),
      ...(portOf(url) ? { port: portOf(url) } : {}),
      endpoint: url,
      ...(parameter ? { parameter } : {}),
      evidence: truncate(redactEvidenceText([title ? `Title: ${title}` : "", out.dbmsHint ? `DBMS hint (safely observed): ${out.dbmsHint}` : "", `Techniques: ${types.join(", ")}`].filter(Boolean).join(" · "))),
      sourceTool: source,
      sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host: hostOf(url), endpoint: url, parameter, vulnClass }),
    }));
    findings++;
  }
  if (findings === 0 && /it looks like the back-end DBMS is/i.test(text)) {
    out.warnings.push("sqlmap: DBMS fingerprint observed without an injectable parameter — recorded as warning, not a finding");
  }
  out.metrics = { findings };
  return out;
}

/* ------------------------------- Commix (§77/§78) ------------------------------- */

export function parseCommixOutput(text: string, source = "commix"): ParsedApi {
  const out = emptyParsedApi();
  let findings = 0;
  const url = text.match(/Target URL:\s*(\S+)/i)?.[1] ?? text.match(/https?:\/\/[^\s'"]+/)?.[0] ?? "";
  const param = text.match(/parameter\s+['"]?([A-Za-z0-9_[\]-]+)['"]?/i)?.[1];
  if (/appears to be injectable|command injection was identified|results can be found/i.test(text) && !/does not appear to be injectable|not injectable/i.test(text)) {
    const vulnClass = "COMMAND_INJECTION";
    out.findings.push(draft({
      title: "OS Command Injection (detection-only confirmation)",
      description: "commix identified a command-injection point using the platform's harmless proof marker. No arbitrary operating-system command was executed (§78).",
      severity: "HIGH",
      confidence: 0.85,
      vulnClass,
      host: hostOf(url),
      ...(portOf(url) ? { port: portOf(url) } : {}),
      endpoint: url,
      ...(param ? { parameter: param } : {}),
      evidence: truncate(redactEvidenceText("commix detection marker confirmed — proof output redacted to the marker classification (§76/§114)")),
      sourceTool: source,
      sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host: hostOf(url), endpoint: url, parameter: param, vulnClass }),
    }));
    findings++;
  }
  out.metrics = { findings };
  return out;
}

/* ------------------------------- SSTImap (§79) ------------------------------- */

export function parseSstimapOutput(text: string, source = "sstimap"): ParsedApi {
  const out = emptyParsedApi();
  let findings = 0;
  const url = text.match(/https?:\/\/[^\s'"]+/)?.[0] ?? "";
  const param = text.match(/parameter\s+['"]?([A-Za-z0-9_[\]-]+)['"]?/i)?.[1];
  const engine = text.match(/identified template engine[:\s]+([A-Za-z0-9_ .-]+)/i)?.[1]?.trim()
    ?? text.match(/template engine[:\s]+([A-Za-z0-9_ .-]+)/i)?.[1]?.trim();
  if (/appears to be injectable|is vulnerable|detected/i.test(text) && !/not vulnerable|does not appear/i.test(text)) {
    const vulnClass = "SSTI";
    out.findings.push(draft({
      title: "Server-Side Template Injection (detection-only confirmation)",
      description: `SSTImap identified template-engine evaluation${engine ? ` (${engine})` : ""} using a non-destructive arithmetic proof marker. No code execution beyond the marker was attempted (§79).`,
      severity: "HIGH",
      confidence: 0.85,
      vulnClass,
      host: hostOf(url),
      ...(portOf(url) ? { port: portOf(url) } : {}),
      endpoint: url,
      ...(param ? { parameter: param } : {}),
      evidence: truncate(redactEvidenceText(`SSTI proof marker evaluated${engine ? `; engine hint: ${engine}` : ""}`)),
      sourceTool: source,
      sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host: hostOf(url), endpoint: url, parameter: param, vulnClass }),
    }));
    findings++;
  }
  out.metrics = { findings };
  return out;
}

/* ------------------------------- WPScan (§81/§82) ------------------------------- */

/** WPScan JSON output: version, plugins, themes, interesting findings. */
export function parseWpscanOutput(text: string, source = "wpscan"): ParsedApi {
  const out = emptyParsedApi();
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { out.warnings.push("wpscan: output is not valid JSON — parser failure, not a clean result (§188)"); return out; }
  if (!isRecord(parsed)) { out.warnings.push("wpscan: unexpected output shape"); return out; }
  const targetUrl = str(parsed.target_url) ?? "";
  const host = hostOf(targetUrl);
  let findings = 0;
  const pushVulns = (componentName: string, component: Record<string, unknown>) => {
    const vulns = Array.isArray(component.vulnerabilities) ? component.vulnerabilities : [];
    for (const v of vulns) {
      if (!isRecord(v)) continue;
      const title = str(v.title) ?? `Known vulnerability in ${componentName}`;
      const refs = isRecord(v.references) ? v.references : {};
      const cves = Array.isArray(refs.cve) ? refs.cve.filter((x): x is string => typeof x === "string") : [];
      const vulnClass = "KNOWN_VULNERABLE_COMPONENT";
      out.findings.push(draft({
        title: `${title} (${componentName})`,
        description: `WPScan enumerated ${componentName} and correlated it with a known vulnerability entry. Correlation is version-based evidence (§81); the platform did not exploit it.`,
        severity: "MEDIUM",
        confidence: 0.7,
        vulnClass,
        host,
        endpoint: targetUrl,
        ...(cves[0] ? { cve: cves[0].startsWith("CVE-") ? cves[0] : `CVE-${cves[0]}` } : {}),
        evidence: truncate(redactEvidenceText(`component: ${componentName}`)),
        sourceTool: source,
        sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host, endpoint: targetUrl, vulnClass, checkId: `${componentName}:${title}` }),
      }));
      findings++;
    }
  };
  if (isRecord(parsed.wordpress_version)) pushVulns("wordpress core", parsed.wordpress_version);
  for (const group of ["plugins", "themes"] as const) {
    const entries = parsed[group];
    if (isRecord(entries)) for (const [name, comp] of Object.entries(entries)) if (isRecord(comp)) pushVulns(`${group.slice(0, -1)} ${name}`, comp);
  }
  const interesting = Array.isArray(parsed.interesting_findings) ? parsed.interesting_findings : [];
  for (const f of interesting) {
    if (!isRecord(f)) continue;
    const toS = str(f.to_s) ?? str(f.url) ?? "interesting finding";
    const vulnClass = "WORDPRESS_CONFIGURATION";
    out.findings.push(draft({
      title: `WordPress configuration observation: ${toS.slice(0, 80)}`,
      description: "WPScan reported a configuration observation for the authorized WordPress asset (§81).",
      severity: "LOW",
      confidence: 0.6,
      vulnClass,
      host,
      endpoint: targetUrl,
      evidence: truncate(redactEvidenceText(toS)),
      sourceTool: source,
      sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host, endpoint: targetUrl, vulnClass, checkId: toS.slice(0, 60) }),
    }));
    findings++;
  }
  out.metrics = { findings };
  return out;
}
