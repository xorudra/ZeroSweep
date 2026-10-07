import { childrenNamed, firstChild, parseXmlLite } from "../network/xml-lite";
import type { NormalizedFinding, NormalizedSoftwareComponent } from "../findings/finding.types";
import { buildRedactedSnippet, normalizeRepoPath, sanitizeDisplayText } from "./paths";
import {
  SecretFingerprintService, classifySecretType, redactSecretsInText, redactedPreview,
} from "./secrets";
import { sourceFingerprint } from "./correlation";
import { isGeneratedOrVendored } from "./detect";

/**
 * Source tool output parsers (Prompt 12 §21–§58). Every parser treats
 * tool output as HOSTILE data (§107): paths are normalized to
 * repository-relative or dropped, text is display-sanitized, and secret
 * VALUES are reduced to fingerprints at parse time — the raw value is
 * never copied into a finding, metric or warning (§101).
 *
 * CWE/OWASP mappings come ONLY from the tool output itself or governed
 * catalog data (§67/§68) — parsers never invent classifications.
 */

export interface ParsedCode {
  findings: NormalizedFinding[];
  components: NormalizedSoftwareComponent[];
  metrics: Record<string, number>;
  warnings: string[];
  records: number;
}

export function emptyParsedCode(): ParsedCode {
  return { findings: [], components: [], metrics: {}, warnings: [], records: 0 };
}

export interface ParserContext {
  /** Stable repository identity used in source fingerprints (§64). */
  repositoryKey: string;
  fingerprints?: SecretFingerprintService;
  /** Tool slug the output came from (provenance). */
  sourceTool: string;
}

const fpService = (ctx: ParserContext): SecretFingerprintService => ctx.fingerprints ?? new SecretFingerprintService();

function clean(text: unknown, max = 1200): string {
  return sanitizeDisplayText(redactSecretsInText(String(text ?? "")), max);
}

function safePath(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  return normalizeRepoPath(raw) ?? undefined;
}

function baseFinding(ctx: ParserContext, partial: Partial<NormalizedFinding> & { title: string }): NormalizedFinding {
  return {
    description: "",
    severity: "MEDIUM",
    confidence: 0.5,
    references: [],
    sourceTool: ctx.sourceTool,
    sourceFingerprint: "",
    ...partial,
  } as NormalizedFinding;
}

function sastFingerprint(ctx: ParserContext, f: { filePath?: string; ruleId?: string; context?: string; toolFingerprint?: string }): string {
  return sourceFingerprint({
    repositoryKey: ctx.repositoryKey,
    filePath: f.filePath ?? "unknown",
    ruleId: f.ruleId ?? "unknown-rule",
    context: f.context,
    toolFingerprint: f.toolFingerprint,
  });
}

/** Secret finding builder — the ONLY way secret hits enter the pipeline.
 *  `rawSecret` is consumed by the fingerprint service and the preview
 *  builder and then dropped; it is never assigned to any output field. */
function secretFinding(
  ctx: ParserContext,
  input: {
    detector: string; ruleId?: string; rawSecret: string; filePath?: string;
    startLine?: number; endLine?: number; commitSha?: string;
    verified?: boolean; description?: string;
  },
): NormalizedFinding {
  const fps = fpService(ctx);
  const fingerprint = fps.fingerprint(input.rawSecret);
  const secretType = classifySecretType(input.detector, input.ruleId);
  const highValue = ["CLOUD_CREDENTIAL", "PRIVATE_KEY", "DATABASE_CREDENTIAL"].includes(secretType);
  return baseFinding(ctx, {
    title: `${input.detector} secret detected${input.filePath ? ` in ${input.filePath}` : ""}`,
    description: clean(input.description ?? `A ${secretType.toLowerCase().replace(/_/g, " ")} was detected by ${input.detector}. The value is never stored — rotate the credential and remove it from history (§43).`),
    severity: input.verified ? "CRITICAL" : highValue ? "HIGH" : "MEDIUM",
    confidence: input.verified ? 0.95 : 0.8,
    filePath: input.filePath,
    startLine: input.startLine,
    endLine: input.endLine,
    ruleId: input.ruleId ?? input.detector,
    remediation: "Rotate the credential immediately, purge it from repository history, and move secrets to the platform secret store (references only).",
    secret: {
      secretType,
      detector: input.detector,
      fingerprint,
      redactedPreview: redactedPreview(input.rawSecret),
      commitSha: input.commitSha,
      verificationStatus: input.verified === true ? "VERIFIED_ACTIVE" : input.verified === false ? "VERIFIED_INACTIVE" : "NOT_VERIFIED",
    },
    // Secret identity (§64): repository + file + the secret's own
    // one-way fingerprint — the same secret found by two tools merges.
    sourceFingerprint: sourceFingerprint({
      repositoryKey: ctx.repositoryKey,
      filePath: input.filePath ?? "unknown",
      ruleId: `secret:${fingerprint}`,
    }),
  });
}

// ── Semgrep (§21) ─────────────────────────────────────────────────────

interface SemgrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string; severity?: string; lines?: string; fingerprint?: string;
    metadata?: { cwe?: string[] | string; owasp?: string[] | string; confidence?: string; impact?: string; likelihood?: string; references?: string[] };
    dataflow_trace?: { intermediate_vars?: { location?: { path?: string; start?: { line?: number }; end?: { line?: number } }; content?: string }[] };
  };
}

export function parseSemgrep(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: { results?: SemgrepResult[]; errors?: unknown[] };
  try { json = JSON.parse(text); } catch { out.warnings.push("semgrep output was not valid JSON"); return out; }
  const severityMap: Record<string, NormalizedFinding["severity"]> = { ERROR: "HIGH", WARNING: "MEDIUM", INFO: "LOW" };
  const confidenceMap: Record<string, number> = { HIGH: 0.9, MEDIUM: 0.6, LOW: 0.3 };
  for (const r of json.results ?? []) {
    const filePath = safePath(r.path);
    if (!filePath) { out.warnings.push("semgrep result dropped: path outside repository"); continue; }
    const cweRaw = Array.isArray(r.extra?.metadata?.cwe) ? r.extra?.metadata?.cwe[0] : r.extra?.metadata?.cwe;
    const cwe = typeof cweRaw === "string" ? /CWE-\d+/i.exec(cweRaw)?.[0].toUpperCase() : undefined;
    const owaspRaw = Array.isArray(r.extra?.metadata?.owasp) ? r.extra?.metadata?.owasp[0] : r.extra?.metadata?.owasp;
    const snippet = buildRedactedSnippet(r.extra?.lines, r.start?.line);
    const codeFlow = (r.extra?.dataflow_trace?.intermediate_vars ?? [])
      .map((v) => {
        const p = v.location?.path ? safePath(v.location.path) : undefined;
        return p ? { label: clean(v.content ?? "taint step", 120), filePath: p, startLine: v.location?.start?.line, endLine: v.location?.end?.line } : null;
      })
      .filter((x): x is NonNullable<typeof x> => x !== null);
    const finding = baseFinding(ctx, {
      title: clean(r.extra?.message ?? r.check_id ?? "Semgrep finding", 300),
      description: clean(r.extra?.message ?? ""),
      severity: severityMap[(r.extra?.severity ?? "").toUpperCase()] ?? "MEDIUM",
      confidence: confidenceMap[(r.extra?.metadata?.confidence ?? "").toUpperCase()] ?? 0.6,
      cwe,
      owaspCategory: typeof owaspRaw === "string" ? clean(owaspRaw, 120) : undefined,
      filePath,
      startLine: r.start?.line,
      endLine: r.end?.line,
      startColumn: r.start?.col,
      endColumn: r.end?.col,
      ruleId: r.check_id,
      evidence: snippet,
      codeFlow: codeFlow.length > 0 ? codeFlow : undefined,
      references: (r.extra?.metadata?.references ?? []).filter((x) => typeof x === "string").slice(0, 5),
      generatedCode: isGeneratedOrVendored(filePath) || undefined,
    });
    finding.sourceFingerprint = sastFingerprint(ctx, { filePath, ruleId: r.check_id, context: r.extra?.lines, toolFingerprint: r.extra?.fingerprint });
    out.findings.push(finding);
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, parseErrors: (json.errors ?? []).length };
  return out;
}

// ── Bandit (§25) ──────────────────────────────────────────────────────

interface BanditResult {
  filename?: string; line_number?: number; line_range?: number[];
  issue_text?: string; issue_severity?: string; issue_confidence?: string;
  test_id?: string; test_name?: string; code?: string;
  cwe?: { id?: number };
}

export function parseBandit(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: { results?: BanditResult[] };
  try { json = JSON.parse(text); } catch { out.warnings.push("bandit output was not valid JSON"); return out; }
  const sev: Record<string, NormalizedFinding["severity"]> = { HIGH: "HIGH", MEDIUM: "MEDIUM", LOW: "LOW" };
  const conf: Record<string, number> = { HIGH: 0.9, MEDIUM: 0.6, LOW: 0.3 };
  for (const r of json.results ?? []) {
    const filePath = safePath(r.filename);
    if (!filePath) { out.warnings.push("bandit result dropped: path outside repository"); continue; }
    const finding = baseFinding(ctx, {
      title: clean(`${r.test_name ?? r.test_id ?? "Bandit issue"}: ${r.issue_text ?? ""}`, 300),
      description: clean(r.issue_text ?? ""),
      severity: sev[(r.issue_severity ?? "").toUpperCase()] ?? "MEDIUM",
      confidence: conf[(r.issue_confidence ?? "").toUpperCase()] ?? 0.5,
      cwe: r.cwe?.id ? `CWE-${r.cwe.id}` : undefined,
      filePath,
      startLine: r.line_number,
      endLine: r.line_range && r.line_range.length > 0 ? r.line_range[r.line_range.length - 1] : r.line_number,
      ruleId: r.test_id,
      evidence: buildRedactedSnippet(r.code, r.line_number),
      generatedCode: isGeneratedOrVendored(filePath) || undefined,
    });
    finding.sourceFingerprint = sastFingerprint(ctx, { filePath, ruleId: r.test_id, context: r.code });
    out.findings.push(finding);
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length };
  return out;
}

// ── Brakeman (§26 — Rails) ────────────────────────────────────────────

interface BrakemanWarning {
  warning_type?: string; check_name?: string; message?: string;
  file?: string; line?: number; code?: string; confidence?: string;
  fingerprint?: string; cwe_id?: number[] | number; link?: string;
}

const BRAKEMAN_SEVERITY: [RegExp, NormalizedFinding["severity"]][] = [
  [/sql injection|command injection|code execution|file access|dangerous send|unsafe reflection/i, "HIGH"],
  [/cross-site scripting|csrf|session settings|redirect|mass assignment/i, "MEDIUM"],
  [/denial of service|information disclosure|warning/i, "LOW"],
];

export function parseBrakeman(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: { warnings?: BrakemanWarning[] };
  try { json = JSON.parse(text); } catch { out.warnings.push("brakeman output was not valid JSON"); return out; }
  const conf: Record<string, number> = { High: 0.9, Medium: 0.6, Weak: 0.3 };
  for (const w of json.warnings ?? []) {
    const filePath = w.file ? safePath(w.file) : undefined;
    if (!filePath) { out.warnings.push("brakeman warning dropped: path outside repository"); continue; }
    const cweId = Array.isArray(w.cwe_id) ? w.cwe_id[0] : w.cwe_id;
    const severity = BRAKEMAN_SEVERITY.find(([re]) => re.test(w.warning_type ?? ""))?.[1] ?? "MEDIUM";
    const finding = baseFinding(ctx, {
      title: clean(`${w.warning_type ?? "Brakeman warning"}: ${w.message ?? ""}`, 300),
      description: clean(w.message ?? ""),
      severity,
      confidence: conf[w.confidence ?? ""] ?? 0.5,
      cwe: cweId ? `CWE-${cweId}` : undefined,
      filePath,
      startLine: w.line,
      endLine: w.line,
      ruleId: w.check_name ? `brakeman.${w.check_name}` : undefined,
      evidence: buildRedactedSnippet(w.code, w.line),
      references: w.link ? [w.link] : [],
      generatedCode: isGeneratedOrVendored(filePath) || undefined,
    });
    finding.sourceFingerprint = sastFingerprint(ctx, { filePath, ruleId: finding.ruleId, context: w.code, toolFingerprint: w.fingerprint });
    out.findings.push(finding);
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length };
  return out;
}

// ── SpotBugs + FindSecBugs (§29 — XML; security findings only) ───────

const SPOTBUGS_SECURITY_TYPES = /^(SQL_|XSS_|COMMAND_INJECTION|PATH_TRAVERSAL|XXE_|SSRF|LDAP_|XPATH_|CRLF_|DESERIALIZATION|WEAK_|HARD_CODE|PREDICTABLE_RANDOM|ECB_MODE|UNSAFE_|OBJECT_DESERIALIZATION)/;

export function parseSpotbugs(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  const parsedXml = parseXmlLite(text);
  if ("error" in parsedXml) { out.warnings.push(`spotbugs output rejected: ${parsedXml.error}`); return out; }
  const root = parsedXml.root;
  const sev: Record<string, NormalizedFinding["severity"]> = { "1": "HIGH", "2": "MEDIUM", "3": "LOW", "4": "LOW", "5": "INFORMATIONAL" };
  let skippedNonSecurity = 0;
  // NOTE: the hardened XML reader lowercases tag/attribute names.
  for (const bug of childrenNamed(root, "buginstance")) {
    const type = bug.attrs.type ?? "";
    const category = bug.attrs.category ?? "";
    if (category !== "SECURITY" && !SPOTBUGS_SECURITY_TYPES.test(type)) { skippedNonSecurity += 1; continue; }
    const method = childrenNamed(bug, "method")[0];
    const sourceLine = firstChild(bug, "sourceline") ?? (method ? firstChild(method, "sourceline") : undefined);
    const rawPath = sourceLine?.attrs.sourcepath ?? sourceLine?.attrs.sourcefile;
    const filePath = rawPath ? safePath(rawPath) : undefined;
    if (!filePath) { out.warnings.push("spotbugs finding dropped: no repository-relative source path"); continue; }
    const startLine = sourceLine?.attrs.start ? Number(sourceLine.attrs.start) : undefined;
    const endLine = sourceLine?.attrs.end ? Number(sourceLine.attrs.end) : startLine;
    const longMessage = firstChild(bug, "longmessage")?.text ?? type;
    const finding = baseFinding(ctx, {
      title: clean(longMessage, 300),
      description: clean(longMessage),
      severity: sev[bug.attrs.priority ?? ""] ?? "MEDIUM",
      confidence: 0.6,
      filePath,
      startLine,
      endLine,
      ruleId: type,
      generatedCode: isGeneratedOrVendored(filePath) || undefined,
    });
    finding.sourceFingerprint = sastFingerprint(ctx, { filePath, ruleId: type, toolFingerprint: bug.attrs.instancehash });
    out.findings.push(finding);
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, nonSecurityBugsSkipped: skippedNonSecurity };
  return out;
}

// ── Gitleaks (§34) ────────────────────────────────────────────────────

interface GitleaksFinding {
  Description?: string; RuleID?: string; File?: string;
  StartLine?: number; EndLine?: number; Secret?: string;
  Commit?: string; Author?: string; Date?: string;
}

export function parseGitleaks(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: GitleaksFinding[];
  try { json = JSON.parse(text); } catch { out.warnings.push("gitleaks output was not valid JSON"); return out; }
  if (!Array.isArray(json)) return out;
  for (const g of json) {
    if (!g.Secret) continue; // nothing to fingerprint — not a usable record
    const filePath = g.File ? safePath(g.File) : undefined;
    out.findings.push(secretFinding(ctx, {
      detector: "gitleaks",
      ruleId: g.RuleID,
      rawSecret: g.Secret,
      filePath,
      startLine: g.StartLine,
      endLine: g.EndLine,
      commitSha: g.Commit,
      description: g.Description,
    }));
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, secrets: out.findings.length };
  return out;
}

// ── TruffleHog (§37 — verification disabled by platform policy) ──────

interface TrufflehogRecord {
  DetectorName?: string; DetectorDescription?: string; Verified?: boolean;
  Raw?: string; RawV2?: string;
  SourceMetadata?: { Data?: { Filesystem?: { file?: string; line?: number }; Git?: { commit?: string; file?: string; line?: number } } };
}

export function parseTrufflehog(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) continue;
    let rec: TrufflehogRecord;
    try { rec = JSON.parse(trimmed); } catch { continue; }
    const raw = rec.Raw ?? rec.RawV2;
    if (!raw || !rec.DetectorName) continue;
    const fs = rec.SourceMetadata?.Data?.Filesystem;
    const git = rec.SourceMetadata?.Data?.Git;
    const filePath = (fs?.file ?? git?.file) ? safePath(fs?.file ?? git?.file) : undefined;
    out.findings.push(secretFinding(ctx, {
      detector: rec.DetectorName,
      ruleId: rec.DetectorName,
      rawSecret: raw,
      filePath,
      startLine: fs?.line ?? git?.line,
      commitSha: git?.commit,
      // Platform policy (§37): verification is DISABLED — adapters never
      // run TruffleHog with verification, so `Verified` is expected to be
      // absent/false in platform output. If a record claims verification
      // it came from an out-of-band run and is recorded as reported.
      verified: rec.Verified === true ? true : undefined,
      description: rec.DetectorDescription,
    }));
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, secrets: out.findings.length };
  return out;
}

// ── OWASP Dependency-Check (§49) ──────────────────────────────────────

interface DepCheckVuln {
  name?: string; severity?: string; description?: string;
  cvssv3?: { baseScore?: number; baseSeverity?: string; vectorString?: string };
  cvssv2?: { score?: number; severity?: string };
  cwes?: string[];
  references?: { url?: string }[];
  vulnerableSoftware?: { software?: { id?: string; versionEndExcluding?: string } }[];
}
interface DepCheckDependency {
  fileName?: string; filePath?: string;
  packages?: { id?: string }[];
  vulnerabilities?: DepCheckVuln[];
}

function depSeverity(raw: string | undefined, score?: number): NormalizedFinding["severity"] {
  const v = (raw ?? "").toUpperCase();
  if (v === "CRITICAL" || (score !== undefined && score >= 9)) return "CRITICAL";
  if (v === "HIGH" || (score !== undefined && score >= 7)) return "HIGH";
  if (v === "MEDIUM" || v === "MODERATE" || (score !== undefined && score >= 4)) return "MEDIUM";
  if (v === "LOW" || (score !== undefined && score > 0)) return "LOW";
  return "MEDIUM";
}

export function parseDependencyCheck(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: { dependencies?: DepCheckDependency[] };
  try { json = JSON.parse(text); } catch { out.warnings.push("dependency-check output was not valid JSON"); return out; }
  for (const dep of json.dependencies ?? []) {
    const manifest = dep.filePath ? safePath(dep.filePath) ?? dep.fileName ?? "unknown" : dep.fileName ?? "unknown";
    for (const pkg of dep.packages ?? []) {
      // package id looks like "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
      const purl = pkg.id ?? "";
      const m = /^pkg:([a-z]+)\/(.+?)@(.+)$/.exec(purl);
      if (m) {
        out.components.push({
          name: m[2].includes("/") && m[1] === "maven" ? m[2].replace("/", ":") : m[2],
          version: m[3], ecosystem: m[1], purl, sourceManifest: manifest,
          scope: "UNKNOWN", dependencyScope: "RUNTIME", licenses: [],
        });
      }
    }
    for (const vuln of dep.vulnerabilities ?? []) {
      const cve = /^CVE-\d{4}-\d+$/i.exec(vuln.name ?? "")?.[0].toUpperCase();
      const pkg = (dep.packages ?? [])[0];
      const purl = pkg?.id;
      const fixed = (vuln.vulnerableSoftware ?? []).map((s) => s.software?.versionEndExcluding).find(Boolean);
      const finding = baseFinding(ctx, {
        title: clean(`${vuln.name ?? "Dependency vulnerability"} in ${dep.fileName ?? "dependency"}`, 300),
        description: clean(vuln.description ?? ""),
        severity: depSeverity(vuln.cvssv3?.baseSeverity ?? vuln.severity, vuln.cvssv3?.baseScore ?? vuln.cvssv2?.score),
        confidence: 0.8,
        cve,
        cwe: (vuln.cwes ?? [])[0] ? (/CWE-\d+/i.exec((vuln.cwes ?? [])[0])?.[0].toUpperCase()) : undefined,
        cvssScore: vuln.cvssv3?.baseScore ?? vuln.cvssv2?.score,
        cvssVector: vuln.cvssv3?.vectorString,
        references: (vuln.references ?? []).map((r) => r.url).filter((u): u is string => typeof u === "string").slice(0, 5),
        componentPurl: purl,
        componentName: purl ? (/^pkg:[a-z]+\/(.+?)@/.exec(purl)?.[1]) : dep.fileName,
        componentVersion: purl ? (/@(.+)$/.exec(purl)?.[1]) : undefined,
        fixedVersion: fixed,
        dependencyScope: "RUNTIME",
        reachability: "UNKNOWN",
      });
      finding.sourceFingerprint = `dep|${purl ?? dep.fileName ?? "unknown"}|${cve ?? vuln.name ?? "unknown"}`;
      out.findings.push(finding);
    }
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, components: out.components.length };
  return out;
}

// ── Grype (§51) ───────────────────────────────────────────────────────

interface GrypeMatch {
  vulnerability?: {
    id?: string; severity?: string; description?: string;
    cvss?: { version?: string; metrics?: { baseScore?: number }; vector?: string }[];
    fix?: { versions?: string[]; state?: string };
    dataSource?: string;
  };
  artifact?: { name?: string; version?: string; type?: string; purl?: string; licenses?: string[]; locations?: { path?: string }[] };
  relatedVulnerabilities?: { id?: string }[];
}

const ECOSYSTEM_BY_GRYPE_TYPE: Record<string, string> = {
  npm: "npm", python: "pypi", gem: "gem", go: "golang", "go-module": "golang",
  java: "maven", jar: "maven", rust: "cargo", php: "composer", deb: "deb", rpm: "rpm", apk: "apk",
};

export function parseGrype(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: { matches?: GrypeMatch[] };
  try { json = JSON.parse(text); } catch { out.warnings.push("grype output was not valid JSON"); return out; }
  const seenComponents = new Set<string>();
  for (const match of json.matches ?? []) {
    const vuln = match.vulnerability ?? {};
    const artifact = match.artifact ?? {};
    const ecosystem = ECOSYSTEM_BY_GRYPE_TYPE[artifact.type ?? ""] ?? artifact.type ?? "unknown";
    const purl = artifact.purl ?? (artifact.name ? `pkg:${ecosystem}/${artifact.name}${artifact.version ? `@${artifact.version}` : ""}` : undefined);
    if (purl && !seenComponents.has(purl)) {
      seenComponents.add(purl);
      out.components.push({
        name: artifact.name ?? "unknown", version: artifact.version, ecosystem,
        purl, sourceManifest: artifact.locations?.[0]?.path ? safePath(artifact.locations[0].path) ?? "scan-target" : "scan-target",
        scope: "UNKNOWN", dependencyScope: "RUNTIME", licenses: artifact.licenses ?? [],
      });
    }
    const cvss = (vuln.cvss ?? []).find((c) => c.version?.startsWith("3")) ?? (vuln.cvss ?? [])[0];
    const cve = /^CVE-\d{4}-\d+$/i.exec(vuln.id ?? "")?.[0].toUpperCase()
      ?? (match.relatedVulnerabilities ?? []).map((r) => /^CVE-\d{4}-\d+$/i.exec(r.id ?? "")?.[0]?.toUpperCase()).find(Boolean);
    const finding = baseFinding(ctx, {
      title: clean(`${vuln.id ?? "Vulnerability"} in ${artifact.name ?? "component"} ${artifact.version ?? ""}`, 300),
      description: clean(vuln.description ?? ""),
      severity: depSeverity(vuln.severity, cvss?.metrics?.baseScore),
      confidence: 0.85,
      cve,
      cvssScore: cvss?.metrics?.baseScore,
      cvssVector: cvss?.vector,
      references: vuln.dataSource ? [vuln.dataSource] : [],
      componentPurl: purl,
      componentName: artifact.name,
      componentVersion: artifact.version,
      fixedVersion: vuln.fix?.state === "fixed" ? (vuln.fix.versions ?? [])[0] : undefined,
      dependencyScope: "RUNTIME",
      reachability: "UNKNOWN",
    });
    finding.sourceFingerprint = `dep|${purl ?? artifact.name ?? "unknown"}|${cve ?? vuln.id ?? "unknown"}`;
    out.findings.push(finding);
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, components: out.components.length };
  return out;
}

// ── SonarQube (§24–§27) ───────────────────────────────────────────────

interface SonarIssue {
  key?: string; rule?: string; severity?: string; type?: string;
  component?: string; line?: number; message?: string; status?: string;
  flows?: { locations?: { component?: string; textRange?: { startLine?: number; endLine?: number }; msg?: string }[] }[];
}

const SONAR_SEVERITY: Record<string, NormalizedFinding["severity"]> = {
  BLOCKER: "CRITICAL", CRITICAL: "HIGH", MAJOR: "MEDIUM", MINOR: "LOW", INFO: "INFORMATIONAL",
};

export function parseSonarIssues(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  let json: { issues?: SonarIssue[] };
  try { json = JSON.parse(text); } catch { out.warnings.push("sonarqube payload was not valid JSON"); return out; }
  let nonSecurity = 0;
  for (const issue of json.issues ?? []) {
    const type = (issue.type ?? "").toUpperCase();
    if (type !== "VULNERABILITY" && type !== "SECURITY_HOTSPOT") { nonSecurity += 1; continue; }
    // component looks like "project-key:path/to/file.java"
    const rawPath = (issue.component ?? "").includes(":") ? (issue.component ?? "").split(":").slice(1).join(":") : issue.component;
    const filePath = rawPath ? safePath(rawPath) : undefined;
    if (!filePath) { out.warnings.push("sonar issue dropped: path outside repository"); continue; }
    const isHotspot = type === "SECURITY_HOTSPOT";
    const codeFlow = (issue.flows ?? []).flatMap((flow) => (flow.locations ?? []).map((loc) => {
      const p = loc.component ? safePath(loc.component.includes(":") ? loc.component.split(":").slice(1).join(":") : loc.component) : undefined;
      return p ? { label: clean(loc.msg ?? "flow step", 120), filePath: p, startLine: loc.textRange?.startLine, endLine: loc.textRange?.endLine } : null;
    })).filter((x): x is NonNullable<typeof x> => x !== null);
    const finding = baseFinding(ctx, {
      title: clean(`${isHotspot ? "Security hotspot" : "Vulnerability"}: ${issue.message ?? issue.rule ?? "SonarQube issue"}`, 300),
      description: clean(issue.message ?? "") + (isHotspot ? " Security hotspots require human review (§27) — they are not confirmed vulnerabilities." : ""),
      severity: SONAR_SEVERITY[(issue.severity ?? "").toUpperCase()] ?? "MEDIUM",
      confidence: isHotspot ? 0.4 : 0.7,
      filePath,
      startLine: issue.line,
      ruleId: issue.rule,
      reviewStatus: isHotspot ? "REVIEW_REQUIRED" : undefined,
      codeFlow: codeFlow.length > 0 ? codeFlow : undefined,
      generatedCode: isGeneratedOrVendored(filePath) || undefined,
    });
    finding.sourceFingerprint = sastFingerprint(ctx, { filePath, ruleId: issue.rule, toolFingerprint: issue.key });
    out.findings.push(finding);
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length, nonSecurityIssuesSkipped: nonSecurity };
  return out;
}

// ── SARIF importer (§31/§32) — CodeQL and other SARIF producers ──────

export const SARIF_MAX_BYTES = 25 * 1024 * 1024;
export const SARIF_MAX_RESULTS = 10000;

interface SarifRule { id?: string; name?: string; properties?: { tags?: string[]; cwe?: string }; defaultConfiguration?: { level?: string } }
interface SarifResult {
  ruleId?: string; level?: string; message?: { text?: string };
  partialFingerprints?: Record<string, string>;
  locations?: { physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number; endLine?: number; startColumn?: number; endColumn?: number; snippet?: { text?: string } } } }[];
  codeFlows?: { threadFlows?: { locations?: { location?: { physicalLocation?: { artifactLocation?: { uri?: string }; region?: { startLine?: number; endLine?: number } }; message?: { text?: string } } }[] }[] }[];
}

/**
 * Hostile-safe SARIF import (§31/§32): size-capped, structure-validated,
 * URIs normalized to repository-relative paths (outside-root results
 * dropped), text redacted + sanitized, rules resolved from the run's
 * own metadata only.
 */
export function importSarif(text: string, ctx: ParserContext): ParsedCode {
  const out = emptyParsedCode();
  if (new TextEncoder().encode(text).length > SARIF_MAX_BYTES) {
    out.warnings.push(`SARIF document exceeds the ${SARIF_MAX_BYTES}-byte import cap (§31)`);
    return out;
  }
  let doc: { runs?: { tool?: { driver?: { name?: string; rules?: SarifRule[] } }; results?: SarifResult[] }[] };
  try { doc = JSON.parse(text); } catch { out.warnings.push("SARIF document was not valid JSON"); return out; }
  const levelSeverity: Record<string, NormalizedFinding["severity"]> = { error: "HIGH", warning: "MEDIUM", note: "LOW", none: "INFORMATIONAL" };
  let total = 0;
  for (const run of doc.runs ?? []) {
    const rules = new Map<string, SarifRule>();
    for (const rule of run.tool?.driver?.rules ?? []) if (rule.id) rules.set(rule.id, rule);
    for (const result of run.results ?? []) {
      if (total >= SARIF_MAX_RESULTS) { out.warnings.push(`SARIF results capped at ${SARIF_MAX_RESULTS} (§31)`); break; }
      total += 1;
      const loc = (result.locations ?? [])[0]?.physicalLocation;
      const uri = loc?.artifactLocation?.uri;
      const filePath = uri ? safePath(uri) : undefined;
      if (!filePath) { out.warnings.push("SARIF result dropped: location outside repository"); continue; }
      const rule = result.ruleId ? rules.get(result.ruleId) : undefined;
      const tags = rule?.properties?.tags ?? [];
      const cwe = tags.map((t) => /cwe[-/]?(\d+)/i.exec(t)?.[1]).find(Boolean)
        ?? (/(\d+)/.exec(rule?.properties?.cwe ?? "")?.[1]);
      const region = loc?.region;
      const codeFlow = (result.codeFlows ?? []).flatMap((cf) => (cf.threadFlows ?? []).flatMap((tf) => (tf.locations ?? []).map((step) => {
        const p = step.location?.physicalLocation?.artifactLocation?.uri ? safePath(step.location.physicalLocation.artifactLocation.uri) : undefined;
        return p ? { label: clean(step.location?.message?.text ?? "dataflow step", 120), filePath: p, startLine: step.location?.physicalLocation?.region?.startLine, endLine: step.location?.physicalLocation?.region?.endLine } : null;
      }))).filter((x): x is NonNullable<typeof x> => x !== null);
      const finding = baseFinding(ctx, {
        title: clean(result.message?.text ?? result.ruleId ?? "SARIF finding", 300),
        description: clean(result.message?.text ?? ""),
        severity: levelSeverity[(result.level ?? rule?.defaultConfiguration?.level ?? "warning").toLowerCase()] ?? "MEDIUM",
        confidence: 0.7,
        cwe: cwe ? `CWE-${cwe}` : undefined,
        filePath,
        startLine: region?.startLine,
        endLine: region?.endLine ?? region?.startLine,
        startColumn: region?.startColumn,
        endColumn: region?.endColumn,
        ruleId: result.ruleId,
        evidence: region?.snippet?.text ? buildRedactedSnippet(region.snippet.text, region.startLine) : undefined,
        codeFlow: codeFlow.length > 0 ? codeFlow : undefined,
        generatedCode: isGeneratedOrVendored(filePath) || undefined,
      });
      const fpValues = Object.values(result.partialFingerprints ?? {});
      finding.sourceFingerprint = sastFingerprint(ctx, {
        filePath, ruleId: result.ruleId,
        context: region?.snippet?.text ? redactSecretsInText(region.snippet.text) : undefined,
        toolFingerprint: fpValues[0],
      });
      out.findings.push(finding);
    }
  }
  out.records = out.findings.length;
  out.metrics = { findings: out.findings.length };
  return out;
}
