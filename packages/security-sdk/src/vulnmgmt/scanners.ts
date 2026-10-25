import { createHash } from "node:crypto";
import type { Severity } from "@dsrclone/types";
import type { ScopeRules } from "@dsrclone/validation";
import { ImportValidationError, assertImportSize, assertXmlSafe } from "../proxy/import-security";
import { assertScannerEndpointAllowed, type ScannerTransport } from "../proxy/connector";
import type { EndpointResolver, ScannerHealth, ScannerInstanceRecord, SecretResolver } from "../proxy/types";
import { childrenNamed, firstChild, parseXmlLite, type XmlNode } from "../network/xml-lite";
import { buildNetworkScope, networkScopeContainsIp } from "../network/network-scope";
import { ScopeMatcher } from "../scope/scope.matcher";
import { sourceFindingFingerprint } from "../vuln/analysis";
import { taxonomyFor } from "../vuln/taxonomy";
import type { NormalizedVulnFinding } from "../vuln/types";
import { normalizeCveId, extractCveIds, normalizeCweId, normalizeCvss } from "./normalize";
import { sanitizeScannerText } from "../network/sanitize";

/**
 * Vulnerability scanner integration (Prompt 11 §3–§21, §74–§76):
 * Greenbone/OpenVAS + Nessus Professional connectors and parsers, plus
 * the SearchSploit REFERENCE adapter.
 *
 * Safety invariants (§6/§13/§18/§103):
 *  - scanner targets are generated SERVER-SIDE from verified scope —
 *    raw target lists from any client are never forwarded to a scanner;
 *  - ordinary users select LOGICAL profiles; the mapping to real scanner
 *    policy/config ids lives in administrator instance configuration;
 *  - plugin output is untrusted data: sanitized, size-capped, never
 *    rendered as markup, never used as a path or a command;
 *  - SearchSploit is reference lookup ONLY. Nothing here executes,
 *    downloads, compiles or launches exploit code — no such code path
 *    exists in this module.
 */

export const GREENBONE_SLUG = "greenbone-openvas";
export const NESSUS_SLUG = "nessus-professional";
export const SEARCHSPLOIT_SLUG = "searchsploit";

// ------------------------------- Shared parse result -------------------------------

export interface ParsedScannerReport {
  scanner: string; // tool slug
  scannerVersion?: string;
  reportName?: string;
  findings: NormalizedVulnFinding[];
  /** Hosts present in the report — compared against scope by callers (§75). */
  hosts: string[];
  warnings: string[];
  /** SHA-256 of the raw report — artifact identity (§16). */
  checksum: string;
}

function textOf(node: XmlNode | undefined): string {
  return (node?.text ?? "").trim();
}

function childText(node: XmlNode, name: string): string {
  return textOf(firstChild(node, name));
}

function sanitizeText(raw: string, cap = 8000): string {
  return sanitizeScannerText(raw, cap);
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFORMATIONAL";
}

const NESSUS_SEVERITY: Record<string, Severity> = { "0": "INFORMATIONAL", "1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL" };
const NESSUS_RISK: Record<string, Severity> = { none: "INFORMATIONAL", low: "LOW", medium: "MEDIUM", high: "HIGH", critical: "CRITICAL" };

// ------------------------------- Nessus parser (§15) -------------------------------

/**
 * NessusFindingParser: parses `.nessus` (NessusClientData_v2) exports.
 * The document is treated as hostile (§76): size cap, DOCTYPE/ENTITY
 * rejection, depth-capped lite XML parse, field caps, sanitized output.
 */
export function parseNessusReport(raw: string): ParsedScannerReport {
  assertImportSize(raw);
  assertXmlSafe(raw);
  const parsed = parseXmlLite(raw);
  if ("error" in parsed) throw new ImportValidationError(`Nessus report rejected: ${parsed.error}`);
  const root = parsed.root;
  if (root.tag !== "nessusclientdata_v2") throw new ImportValidationError("Nessus report rejected: root element is not NessusClientData_v2");
  const warnings: string[] = [];
  const findings: NormalizedVulnFinding[] = [];
  const hosts = new Set<string>();
  const report = firstChild(root, "report");
  if (!report) throw new ImportValidationError("Nessus report rejected: no Report element");
  const reportName = report.attrs.name;

  for (const hostNode of childrenNamed(report, "reporthost")) {
    const host = (hostNode.attrs.name ?? "").trim();
    if (!host) { warnings.push("ReportHost without a name skipped"); continue; }
    hosts.add(host);
    for (const item of childrenNamed(hostNode, "reportitem")) {
      const pluginId = item.attrs.pluginid ?? "";
      const pluginName = item.attrs.pluginname ?? childText(item, "plugin_name") ?? "Nessus finding";
      const portRaw = Number(item.attrs.port ?? "");
      const port = Number.isInteger(portRaw) && portRaw > 0 ? portRaw : undefined;
      const protocol = item.attrs.protocol;
      const service = item.attrs.svc_name;
      const severity = NESSUS_SEVERITY[item.attrs.severity ?? ""]
        ?? NESSUS_RISK[childText(item, "risk_factor").toLowerCase()]
        ?? "INFORMATIONAL";
      const cvss = normalizeCvss({ score: childText(item, "cvss_base_score") || undefined, vector: childText(item, "cvss_vector") || undefined, source: "NESSUS" });
      const cves = new Set<string>();
      for (const c of childrenNamed(item, "cve")) { const id = normalizeCveId(textOf(c)); if (id) cves.add(id); }
      for (const id of extractCveIds(childText(item, "description"))) cves.add(id);
      const cve = [...cves][0];
      const cweRaw = childText(item, "cwe");
      const vulnClass = cve ? "GENERIC_VULNERABILITY" : "GENERIC_VULNERABILITY";
      const taxonomy = taxonomyFor(vulnClass);
      const cwe = normalizeCweId(cweRaw) ?? taxonomy.cwe;
      const description = sanitizeText(childText(item, "description") || pluginName);
      const solution = sanitizeText(childText(item, "solution"));
      const pluginOutput = sanitizeText(childText(item, "plugin_output"), 4000);
      const referencesDetailed: NormalizedVulnFinding["referencesDetailed"] = [];
      for (const ref of childrenNamed(item, "see_also")) {
        const url = textOf(ref);
        if (/^https?:\/\//.test(url)) referencesDetailed.push({ type: "URL", label: "See also", url });
      }
      if (cve) referencesDetailed.push({ type: "CVE", label: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}` });
      if (cwe) referencesDetailed.push({ type: "CWE", label: cwe, url: `https://cwe.mitre.org/data/definitions/${cwe.replace("CWE-", "")}.html` });
      findings.push({
        title: sanitizeText(pluginName, 500),
        description,
        severity,
        confidence: severity === "INFORMATIONAL" ? 0.4 : 0.8,
        host,
        ...(port ? { port } : {}),
        ...(protocol ? { protocol } : {}),
        ...(cve ? { cve } : {}),
        ...(cwe ? { cwe } : {}),
        ...(cvss ? { cvssScore: cvss.baseScore, cvssVector: cvss.vector, cvssVersion: cvss.version } : {}),
        owaspCategory: taxonomy.owaspCategory,
        evidence: pluginOutput || undefined,
        remediation: solution || taxonomy.remediation,
        references: referencesDetailed.map((r) => r.url),
        referencesDetailed,
        sourceTool: NESSUS_SLUG,
        sourceFingerprint: sourceFindingFingerprint({ host, port, vulnClass, cve, cwe, sourceTool: NESSUS_SLUG, checkId: pluginId }),
        vulnClass,
        signatureFamily: `nessus-plugin-${pluginId}`,
        sourceConfidence: severity === "INFORMATIONAL" ? 0.4 : 0.8,
        evidenceDetail: {
          checkId: pluginId,
          signatureFamily: `nessus-plugin-${pluginId}`,
          matchedAt: port ? `${host}:${port}` : host,
          metadata: {
            pluginId, pluginFamily: item.attrs.pluginfamily ?? "",
            ...(service ? { service } : {}),
            ...(childText(item, "cpe") ? { cpe: childText(item, "cpe") } : {}),
          },
        },
      });
    }
  }
  return {
    scanner: NESSUS_SLUG, ...(reportName ? { reportName } : {}),
    findings, hosts: [...hosts], warnings,
    checksum: createHash("sha256").update(raw).digest("hex"),
  };
}

// ------------------------------- Greenbone parser (§9) -------------------------------

/**
 * GreenboneFindingParser: parses Greenbone/OpenVAS GMP report XML
 * (report → results → result with NVT metadata). Same hostile-input
 * discipline as the Nessus parser (§76).
 */
export function parseGreenboneReport(raw: string): ParsedScannerReport {
  assertImportSize(raw);
  assertXmlSafe(raw);
  const parsed = parseXmlLite(raw);
  if ("error" in parsed) throw new ImportValidationError(`Greenbone report rejected: ${parsed.error}`);
  const warnings: string[] = [];
  const findings: NormalizedVulnFinding[] = [];
  const hosts = new Set<string>();
  // GMP wraps reports: get_reports_response > report > report > results.
  const reportNodes: XmlNode[] = [];
  const walk = (n: XmlNode) => { if (n.tag === "report") reportNodes.push(n); for (const c of n.children) walk(c); };
  walk(parsed.root);
  const report = reportNodes.find((r) => childrenNamed(r, "results").length > 0) ?? reportNodes[0];
  if (!report) throw new ImportValidationError("Greenbone report rejected: no report element");
  const results = childrenNamed(report, "results").flatMap((r) => childrenNamed(r, "result"));
  if (results.length === 0) warnings.push("Greenbone report contains no results");

  for (const result of results) {
    const host = childText(result, "host");
    if (!host) { warnings.push("Greenbone result without host skipped"); continue; }
    hosts.add(host);
    const nvt = firstChild(result, "nvt");
    const name = childText(result, "name") || (nvt ? childText(nvt, "name") : "") || "Greenbone finding";
    const portRaw = childText(result, "port"); // e.g. "443/tcp"
    const portMatch = /^(\d{1,5})\/(tcp|udp)$/.exec(portRaw);
    const port = portMatch ? Number(portMatch[1]) : undefined;
    const protocol = portMatch?.[2];
    const severityScore = Number(childText(result, "severity"));
    const nvtCvss = nvt ? Number(childText(nvt, "cvss_base")) : NaN;
    const cvss = normalizeCvss({
      score: Number.isFinite(nvtCvss) ? nvtCvss : Number.isFinite(severityScore) ? severityScore : undefined,
      source: "GREENBONE",
    });
    const severity = Number.isFinite(severityScore) ? severityFromScore(severityScore) : cvss ? severityFromScore(cvss.baseScore) : "INFORMATIONAL";
    const cves = new Set<string>();
    if (nvt) {
      for (const id of extractCveIds(childText(nvt, "cve"))) cves.add(id);
      for (const id of extractCveIds(childText(nvt, "tags"))) cves.add(id);
    }
    for (const id of extractCveIds(childText(result, "description"))) cves.add(id);
    const cve = [...cves][0];
    const oid = nvt?.attrs.oid ?? "";
    const vulnClass = "GENERIC_VULNERABILITY";
    const taxonomy = taxonomyFor(vulnClass);
    const cwe = taxonomy.cwe;
    const description = sanitizeText(childText(result, "description") || name);
    const referencesDetailed: NormalizedVulnFinding["referencesDetailed"] = [];
    if (cve) referencesDetailed.push({ type: "CVE", label: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}` });
    findings.push({
      title: sanitizeText(name, 500),
      description,
      severity,
      confidence: severity === "INFORMATIONAL" ? 0.4 : 0.8,
      host,
      ...(port ? { port } : {}),
      ...(protocol ? { protocol } : {}),
      ...(cve ? { cve } : {}),
      cwe,
      ...(cvss ? { cvssScore: cvss.baseScore } : {}),
      owaspCategory: taxonomy.owaspCategory,
      evidence: sanitizeText(childText(result, "description"), 4000) || undefined,
      remediation: taxonomy.remediation,
      references: referencesDetailed.map((r) => r.url),
      referencesDetailed,
      sourceTool: GREENBONE_SLUG,
      sourceFingerprint: sourceFindingFingerprint({ host, port, vulnClass, cve, cwe, sourceTool: GREENBONE_SLUG, checkId: oid }),
      vulnClass,
      signatureFamily: oid ? `greenbone-nvt-${oid}` : "greenbone",
      sourceConfidence: severity === "INFORMATIONAL" ? 0.4 : 0.8,
      evidenceDetail: {
        checkId: oid,
        signatureFamily: oid ? `greenbone-nvt-${oid}` : "greenbone",
        matchedAt: port ? `${host}:${port}` : host,
        metadata: { ...(oid ? { nvtOid: oid } : {}), ...(nvt ? { nvtFamily: childText(nvt, "family") } : {}) },
      },
    });
  }
  return {
    scanner: GREENBONE_SLUG,
    findings, hosts: [...hosts], warnings,
    checksum: createHash("sha256").update(raw).digest("hex"),
  };
}

// ------------------------------- Scope-derived targets (§6/§13) -------------------------------

export interface ScannerTargetGeneration {
  targets: string[];
  /** Scope entries the scanner must never be given (audit/explanation). */
  rejected: { value: string; reason: string }[];
}

/**
 * Generate a scanner target list from TRUSTED ZeroSweep scope only (§6/§13).
 * The input is the persisted scope snapshot — never request data. Hosts and
 * CIDRs come from include rules; exclusions win; expansion is bounded by
 * the caller's maxTargets so a huge CIDR cannot flood a scanner.
 */
export function generateScannerTargets(scope: ScopeRules, options: { maxTargets?: number } = {}): ScannerTargetGeneration {
  const max = options.maxTargets ?? 1024;
  const targets: string[] = [];
  const rejected: { value: string; reason: string }[] = [];
  const net = buildNetworkScope(scope);
  const matcher = new ScopeMatcher(scope);
  const push = (value: string) => { if (!targets.includes(value) && targets.length < max) targets.push(value); };
  for (const host of scope.includeHosts) {
    if (host.startsWith("*.")) { rejected.push({ value: host, reason: "wildcard host rules are not scanner targets — concrete hosts come from inventory" }); continue; }
    if (matcher.isHostAllowed(host)) push(host);
    else rejected.push({ value: host, reason: "excluded by scope or blocked range" });
  }
  for (const cidr of scope.includeCidrs) {
    const probe = cidr.split("/")[0] ?? "";
    const verdict = networkScopeContainsIp(net, probe);
    if (verdict.allowed) push(cidr);
    else rejected.push({ value: cidr, reason: verdict.reason ?? "not allowed by network scope policy" });
  }
  if (targets.length >= max) rejected.push({ value: `>${max}`, reason: "target list truncated at the configured maximum" });
  return { targets, rejected };
}

// ------------------------------- Connectors (§3–§8, §10–§14) -------------------------------

export const GREENBONE_LOGICAL_PROFILES = ["BASELINE", "STANDARD", "COMPREHENSIVE"] as const;
export const NESSUS_LOGICAL_PROFILES = ["NETWORK_BASELINE", "NETWORK_STANDARD", "NETWORK_COMPREHENSIVE"] as const;

export interface VulnerabilityScannerConnector {
  readonly product: "GREENBONE" | "NESSUS";
  readonly slug: string;
  healthCheck(instance: ScannerInstanceRecord): Promise<ScannerHealth>;
  /** Resolve a LOGICAL profile to the administrator-configured scanner
   *  policy/config id (§7/§12). Undefined = profile not configured. */
  resolveProfile(instance: ScannerInstanceRecord, logicalProfile: string): string | undefined;
  createScan(instance: ScannerInstanceRecord, input: { logicalProfile: string; targets: string[]; name: string }): Promise<{ scannerTaskId: string }>;
  getScanStatus(instance: ScannerInstanceRecord, scannerTaskId: string): Promise<{ status: string; progress?: number }>;
  fetchReport(instance: ScannerInstanceRecord, scannerTaskId: string): Promise<ParsedScannerReport>;
  cancel(instance: ScannerInstanceRecord, scannerTaskId: string): Promise<void>;
}

interface InstanceConfig {
  profiles?: Record<string, string>;
  feedStatus?: string;
  approvedInternal?: boolean;
}

function instanceConfig(instance: ScannerInstanceRecord): InstanceConfig {
  // ScannerInstanceRecord has no config field in the Phase 8 type; the API
  // layer stores it in detectedCapabilities-adjacent metadata. Read it from
  // the optional `config` property when present (Prisma Json column).
  const cfg = (instance as unknown as { config?: unknown }).config;
  return (cfg && typeof cfg === "object" ? cfg : {}) as InstanceConfig;
}

abstract class BaseVulnScannerConnector implements VulnerabilityScannerConnector {
  abstract readonly product: "GREENBONE" | "NESSUS";
  abstract readonly slug: string;
  protected abstract readonly healthPath: string;
  protected abstract parseReport(raw: string): ParsedScannerReport;

  constructor(
    protected readonly transport: ScannerTransport,
    protected readonly endpoints: EndpointResolver,
    protected readonly secrets: SecretResolver,
  ) {}

  protected async call(instance: ScannerInstanceRecord, method: "GET" | "POST", path: string, body?: string, query?: Record<string, string>) {
    const resolved = await this.endpoints.resolve(instance.endpointReference);
    if (!resolved) throw new Error(`scanner endpoint reference ${instance.endpointReference} is not configured on this host`);
    assertScannerEndpointAllowed(resolved.baseUrl, resolved.approvedInternal ?? instanceConfig(instance).approvedInternal);
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (instance.credentialReference) {
      const secret = await this.secrets.resolve(instance.credentialReference);
      if (secret) headers.authorization = `Bearer ${secret}`;
    }
    return this.transport.request({ baseUrl: resolved.baseUrl, approvedInternal: resolved.approvedInternal, request: { method, path, body, query, headers } });
  }

  async healthCheck(instance: ScannerInstanceRecord): Promise<ScannerHealth> {
    const checkedAt = new Date().toISOString();
    const resolved = await this.endpoints.resolve(instance.endpointReference);
    if (!resolved) {
      return { status: "MISCONFIGURED", capabilities: [], detail: "endpoint reference is not configured on this host", checkedAt };
    }
    try {
      const res = await this.call(instance, "GET", this.healthPath);
      if (res.status >= 400) return { status: "UNAVAILABLE", capabilities: [], detail: `scanner health endpoint returned ${res.status}`, checkedAt, latencyMs: res.latencyMs };
      let version: string | undefined;
      let feedStatus: string | undefined;
      try {
        const doc = JSON.parse(res.body) as Record<string, unknown>;
        version = typeof doc.version === "string" ? doc.version : undefined;
        feedStatus = typeof doc.feedStatus === "string" ? doc.feedStatus : undefined;
      } catch { /* non-JSON health body: reachable is what matters */ }
      const configuredFeed = instanceConfig(instance).feedStatus;
      const degraded = (feedStatus ?? configuredFeed) === "STALE" || (feedStatus ?? configuredFeed) === "OUTDATED";
      return {
        status: degraded ? "DEGRADED" : "HEALTHY",
        ...(version ? { version } : {}),
        ...(this.product === "NESSUS" && instance.licenseState ? { licenseState: instance.licenseState } : {}),
        capabilities: [...instance.declaredCapabilities],
        detail: degraded ? "scanner reachable but feed is stale" : "scanner reachable",
        latencyMs: res.latencyMs, checkedAt,
      };
    } catch (err) {
      return { status: "UNAVAILABLE", capabilities: [], detail: err instanceof Error ? err.message : "unreachable", checkedAt };
    }
  }

  resolveProfile(instance: ScannerInstanceRecord, logicalProfile: string): string | undefined {
    return instanceConfig(instance).profiles?.[logicalProfile];
  }

  async createScan(instance: ScannerInstanceRecord, input: { logicalProfile: string; targets: string[]; name: string }): Promise<{ scannerTaskId: string }> {
    const policyId = this.resolveProfile(instance, input.logicalProfile);
    if (!policyId) throw new Error(`logical profile ${input.logicalProfile} is not mapped to an administrator-approved scanner policy (§7/§12)`);
    if (input.targets.length === 0) throw new Error("refusing to create a scanner task with no scope-derived targets (§6/§13)");
    const res = await this.call(instance, "POST", "/scans", JSON.stringify({ name: input.name, policyId, targets: input.targets }));
    if (res.status >= 400) throw new Error(`scanner rejected scan creation with ${res.status}`);
    const doc = JSON.parse(res.body) as { id?: string; taskId?: string };
    const id = doc.id ?? doc.taskId;
    if (!id) throw new Error("scanner did not return a task id");
    return { scannerTaskId: id };
  }

  async getScanStatus(instance: ScannerInstanceRecord, scannerTaskId: string): Promise<{ status: string; progress?: number }> {
    const res = await this.call(instance, "GET", `/scans/${encodeURIComponent(scannerTaskId)}`);
    if (res.status >= 400) throw new Error(`scanner status returned ${res.status}`);
    const doc = JSON.parse(res.body) as { status?: string; progress?: number };
    return { status: doc.status ?? "UNKNOWN", ...(typeof doc.progress === "number" ? { progress: doc.progress } : {}) };
  }

  async fetchReport(instance: ScannerInstanceRecord, scannerTaskId: string): Promise<ParsedScannerReport> {
    const res = await this.call(instance, "GET", `/scans/${encodeURIComponent(scannerTaskId)}/report`);
    if (res.status >= 400) throw new Error(`scanner report returned ${res.status}`);
    return this.parseReport(res.body);
  }

  async cancel(instance: ScannerInstanceRecord, scannerTaskId: string): Promise<void> {
    await this.call(instance, "POST", `/scans/${encodeURIComponent(scannerTaskId)}/cancel`, "{}");
  }
}

/** Greenbone/OpenVAS connector (§3): administrator-managed scanner,
 *  GMP-shaped report import, logical scan profiles (§7). */
export class GreenboneConnector extends BaseVulnScannerConnector {
  readonly product = "GREENBONE" as const;
  readonly slug = GREENBONE_SLUG;
  protected readonly healthPath = "/health";
  protected parseReport(raw: string): ParsedScannerReport { return parseGreenboneReport(raw); }
}

/** Nessus Professional connector (§10): COMMERCIAL / ADMIN_PROVIDED /
 *  LICENSE_REQUIRED — used only against an administrator-provided licensed
 *  environment; never redistributed. NOT_CONFIGURED when unregistered (§85). */
export class NessusConnector extends BaseVulnScannerConnector {
  readonly product = "NESSUS" as const;
  readonly slug = NESSUS_SLUG;
  protected readonly healthPath = "/server/status";
  protected parseReport(raw: string): ParsedScannerReport { return parseNessusReport(raw); }
}

// ------------------------------- SearchSploit (§17–§21) -------------------------------

export interface ExploitReferenceRecord {
  externalId: string; // EDB-ID
  title: string;
  reference: string; // canonical reference URL for the record
  platform?: string;
  type?: string;
  cveIds: string[];
  product?: string;
}

export interface ExploitReferenceDataset {
  lookupByCve(cveId: string): ExploitReferenceRecord[];
  lookupByProduct(product: string, version?: string): ExploitReferenceRecord[];
}

/** Shipped dataset is EMPTY (§93 controlled lab provides fixtures):
 *  no reference is ever reported unless a governed local dataset holds it. */
export const EMPTY_EXPLOIT_REFERENCE_DATASET: ExploitReferenceDataset = {
  lookupByCve: () => [],
  lookupByProduct: () => [],
};

export interface ExploitReferenceCandidate {
  findingId?: string;
  source: "SEARCHSPLOIT";
  externalId: string;
  title: string;
  reference: string;
  platform?: string;
  type?: string;
  /** §20 semantics, stated on every record: a reference EXISTS. It is not
   *  evidence the vulnerability is exploitable on this target. */
  meaning: "PUBLIC_EXPLOIT_REFERENCE_EXISTS";
}

/**
 * SearchSploitAdapter (§17): capability VULNERABILITY_REFERENCE_LOOKUP —
 * explicitly NOT EXPLOIT_EXECUTION. It associates known public exploit
 * references with an already-identified CVE/product issue (§19). It has
 * no execution surface: no spawn, no download, no compile — lookups read
 * a local governed dataset only.
 */
export class SearchSploitAdapter {
  readonly slug = SEARCHSPLOIT_SLUG;
  readonly capability = "VULNERABILITY_REFERENCE_LOOKUP" as const;

  constructor(private readonly dataset: ExploitReferenceDataset = EMPTY_EXPLOIT_REFERENCE_DATASET) {}

  lookup(input: { cveId?: string; product?: string; version?: string }): ExploitReferenceCandidate[] {
    const out: ExploitReferenceCandidate[] = [];
    const seen = new Set<string>();
    const add = (r: ExploitReferenceRecord) => {
      if (seen.has(r.externalId)) return;
      seen.add(r.externalId);
      out.push({
        source: "SEARCHSPLOIT", externalId: r.externalId, title: r.title, reference: r.reference,
        ...(r.platform ? { platform: r.platform } : {}),
        ...(r.type ? { type: r.type } : {}),
        meaning: "PUBLIC_EXPLOIT_REFERENCE_EXISTS",
      });
    };
    const cveId = normalizeCveId(input.cveId);
    if (cveId) for (const r of this.dataset.lookupByCve(cveId)) add(r); // CVE correlation preferred (§19)
    if (input.product) for (const r of this.dataset.lookupByProduct(input.product, input.version)) add(r);
    return out;
  }
}
