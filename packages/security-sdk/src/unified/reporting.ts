import { createHash } from "node:crypto";
import { redactEvidenceText } from "../vuln/redact";
import { escapeHtml, sanitizeImportedText } from "./sanitize";

/**
 * ReportingEngine (Prompt 20 §55–§70).
 *
 * A report is an IMMUTABLE SNAPSHOT (§56) of stored records at a point
 * in time: later finding changes never alter an issued report — they
 * produce a new version with its own snapshot. Generation reads stored
 * state only; it never triggers a scan or a validation. All content is
 * sanitized and redacted at snapshot-build time (§63), so every format
 * rendered from the snapshot inherits the protection. Empty scope
 * yields an honest empty report ("no data in scope") — never demo
 * numbers.
 */

export const REPORT_TYPES = [
  "EXECUTIVE", "TECHNICAL_VAPT", "WEB", "NETWORK", "API", "CLOUD",
  "CONTAINER_KUBERNETES", "SOURCE_SCA", "IDENTITY", "MOBILE", "BINARY",
  "WIRELESS", "COMPLIANCE", "REMEDIATION", "RETEST",
  // Prompt 37 §65: the V2 report-type vocabulary. Each name maps onto
  // the same governed source domains below — no new report engine.
  "WEB_VAPT", "API_VAPT", "NETWORK_VAPT", "CLOUD_SECURITY",
  "CONTAINER_SECURITY", "KUBERNETES_SECURITY", "MOBILE_VAPT",
  "BINARY_SECURITY", "SAST", "EASM", "FULL_SECURITY_ASSESSMENT",
  "REMEDIATION_VERIFICATION", "CUSTOM",
] as const;
export type ReportType = (typeof REPORT_TYPES)[number];

export const REPORT_STATUSES = ["DRAFT", "GENERATING", "READY", "FAILED", "ARCHIVED"] as const;
export const REPORT_CLASSIFICATIONS = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] as const;
export const DEFAULT_REPORT_CLASSIFICATION = "CONFIDENTIAL";
export const REPORT_APPROVAL_FLOW = ["DRAFT", "REVIEW", "APPROVED", "ISSUED"] as const;

/** §55: which source domains each report type covers (empty = all). */
export const REPORT_TYPE_DOMAINS: Record<ReportType, string[]> = {
  EXECUTIVE: [],
  TECHNICAL_VAPT: [],
  WEB: ["WEB"],
  NETWORK: ["NETWORK"],
  API: ["API"],
  CLOUD: ["CLOUD"],
  CONTAINER_KUBERNETES: ["CONTAINER", "KUBERNETES"],
  SOURCE_SCA: ["SAST", "SCA", "SECRET"],
  IDENTITY: ["IDENTITY"],
  MOBILE: ["MOBILE"],
  BINARY: ["BINARY"],
  WIRELESS: ["WIRELESS"],
  COMPLIANCE: [],
  REMEDIATION: [],
  RETEST: [],
  WEB_VAPT: ["WEB"],
  API_VAPT: ["API"],
  NETWORK_VAPT: ["NETWORK"],
  CLOUD_SECURITY: ["CLOUD"],
  CONTAINER_SECURITY: ["CONTAINER"],
  KUBERNETES_SECURITY: ["KUBERNETES"],
  MOBILE_VAPT: ["MOBILE"],
  BINARY_SECURITY: ["BINARY"],
  SAST: ["SAST"],
  EASM: ["EASM"],
  FULL_SECURITY_ASSESSMENT: [],
  REMEDIATION_VERIFICATION: [],
  CUSTOM: [],
};

export interface ReportFindingInput {
  id: string;
  title: string;
  description: string;
  severity: string;
  priority?: string | null;
  riskScore?: number | null;
  verificationStatus: string;
  lifecycleStatus: string;
  sourceDomain?: string | null;
  category?: string | null;
  cve?: string | null;
  cwe?: string | null;
  cvssScore?: number | null;
  epssScore?: number | null;
  kevListed?: boolean;
  host?: string | null;
  endpoint?: string | null;
  assetRef?: string | null;
  remediation?: string | null;
  evidenceSummaries?: string[];
  references?: { label: string; url: string }[];
  retestStatus?: string | null;
  sources?: string[];
  evidenceFingerprints?: string[];
  firstSeen: string;
}

export interface ReportTemplateView {
  id: string;
  name: string;
  organizationName?: string | null;
  logoRef?: string | null;
  sections: string[];
  severityDefinitions: Record<string, string>;
  footer?: string | null;
  classification: string;
  customBlocks: { title: string; text: string }[];
}

/** Governed section catalog (§68) — templates pick from these only. */
export const REPORT_SECTION_CATALOG = [
  "COVER", "EXECUTIVE_SUMMARY", "SCOPE", "METHODOLOGY", "RISK_SUMMARY",
  "FINDING_SUMMARY", "DETAILED_FINDINGS", "EVIDENCE", "REMEDIATION", "APPENDICES",
  // Prompt 37 §68: the full V2 section catalog (additive — templates
  // written against the Prompt 20 catalog remain valid).
  "DOCUMENT_CONTROL", "CONFIDENTIALITY", "ENGAGEMENT_OVERVIEW", "OUT_OF_SCOPE",
  "TOOLS", "COVERAGE", "RISK_MODEL", "FINDINGS_SUMMARY", "ATTACK_SURFACE",
  "ATTACK_PATHS", "REMEDIATION_SUMMARY", "VERIFICATION_RESULTS", "LIMITATIONS",
  "CONCLUSION",
] as const;

export type TemplateValidation = { ok: true } | { ok: false; error: string };

/** §68: templates carry branding + structure. Executable template code
 *  (script tags, template expressions, event handlers) is refused. */
export function validateReportTemplate(input: { sections: string[]; customBlocks?: { title: string; text: string }[]; footer?: string | null }): TemplateValidation {
  for (const s of input.sections) {
    if (!(REPORT_SECTION_CATALOG as readonly string[]).includes(s)) {
      return { ok: false, error: `section ${s} is not in the governed catalog (§68)` };
    }
  }
  const executable = /(<script|<%|{{|}}|on\w+\s*=|javascript:)/i;
  for (const block of input.customBlocks ?? []) {
    if (executable.test(block.text) || executable.test(block.title)) {
      return { ok: false, error: "custom blocks are static text only — executable template content is refused (§68)" };
    }
  }
  if (input.footer && executable.test(input.footer)) {
    return { ok: false, error: "footer must be static text (§68)" };
  }
  return { ok: true };
}

/** §66: version arithmetic — v1 → v1.1 (minor) or v2 (major). */
export function nextReportVersion(current: string, kind: "minor" | "major"): string {
  const m = /^v(\d+)(?:\.(\d+))?$/.exec(current.trim());
  if (!m) return "v1";
  const major = Number(m[1]);
  const minor = Number(m[2] ?? 0);
  return kind === "major" ? `v${major + 1}` : `v${major}.${minor + 1}`;
}

/** §67: approval flow transitions. */
export function canTransitionReportApproval(from: string, to: string): boolean {
  const idx = (REPORT_APPROVAL_FLOW as readonly string[]).indexOf(from);
  const next = (REPORT_APPROVAL_FLOW as readonly string[]).indexOf(to);
  return idx >= 0 && next === idx + 1;
}

export interface ReportSnapshotDocument {
  reportId: string;
  title: string;
  type: ReportType;
  classification: string;
  organizationName?: string;
  generatedAt: string;
  generatedBy: string;
  version: string;
  period?: { start?: string; end?: string };
  scopeNote: string;
  isEmpty: boolean;
  executiveSummary: {
    overallRiskScore: number | null;
    totalFindings: number;
    bySeverity: Record<string, number>;
    criticalAndHigh: number;
    kevFindings: number;
    internetFacingFindings: number;
    verifiedFindings: number;
    slaOverdue: number;
    topAffectedAssets: { asset: string; findings: number; worstSeverity: string }[];
    keyRecommendations: string[];
    note: string;
  };
  findings: ReportFindingInput[];
  sections: string[];
  severityDefinitions: Record<string, string>;
  footer?: string;
  customBlocks: { title: string; text: string }[];
  watermark: string;
}

export interface BuildSnapshotInput {
  reportId: string;
  title: string;
  type: ReportType;
  generatedBy: string;
  generatedAt: Date;
  version: string;
  classification?: string;
  period?: { start?: string; end?: string };
  template?: ReportTemplateView;
  findings: ReportFindingInput[];
  slaOverdueIds?: string[];
  internetFacingIds?: string[];
}

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

/** §63/§109: report-level redaction — the platform evidence redactor
 *  plus PEM private-key blocks, which must never survive into a report
 *  in any format. */
export function redactReportText(text: string): string {
  return redactEvidenceText(text)
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED PRIVATE KEY]")
    .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*$/g, "[REDACTED PRIVATE KEY]")
    // Prompt 37 §90: assignment-shaped secrets (password: x, token: x,
    // api-key: x) are masked HERE, at snapshot-build time, so every
    // rendering and every client exposure inherits the protection and
    // the §91 redaction preview passes for platform-built snapshots.
    .replace(/\b(password|passwd|pwd)\s*[:=]\s*\S+/gi, "$1: [REDACTED]")
    .replace(/\b(api[-_ ]?key|access[-_ ]?token|secret[-_ ]?key|auth[-_ ]?token|token)\s*[:=]\s*\S+/gi, "$1: [REDACTED]")
    .replace(/\bcookie\s*[:=]\s*[^\n;]+/gi, "cookie: [REDACTED]");
}

/**
 * Build the snapshot document. Findings are filtered to the report
 * type's domains, sanitized, and evidence-redacted HERE — once — so
 * PDF/HTML/JSON/CSV all inherit the same protected content (§63/§109).
 */
export function buildReportSnapshot(input: BuildSnapshotInput): { document: ReportSnapshotDocument; contentHash: string } {
  const domains = REPORT_TYPE_DOMAINS[input.type];
  const scoped = input.findings.filter((f) => domains.length === 0 || (f.sourceDomain && domains.includes(f.sourceDomain)));
  const findings: ReportFindingInput[] = scoped.map((f) => ({
    ...f,
    title: sanitizeImportedText(f.title, 512),
    description: redactReportText(sanitizeImportedText(f.description, 20_000)),
    evidenceSummaries: (f.evidenceSummaries ?? []).map((e) => redactReportText(sanitizeImportedText(e, 4_000))),
    remediation: f.remediation ? redactReportText(sanitizeImportedText(f.remediation, 4_000)) : f.remediation,
  }));

  const bySeverity: Record<string, number> = {};
  for (const f of findings) bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
  const kevFindings = findings.filter((f) => f.kevListed).length;
  const verifiedFindings = findings.filter((f) => f.verificationStatus === "VERIFIED" || f.verificationStatus === "CONFIRMED").length;
  const internetFacing = input.internetFacingIds ? findings.filter((f) => input.internetFacingIds!.includes(f.id)).length : 0;
  const slaOverdue = input.slaOverdueIds ? findings.filter((f) => input.slaOverdueIds!.includes(f.id)).length : 0;

  const assetCounts = new Map<string, { findings: number; worst: number }>();
  for (const f of findings) {
    const asset = f.assetRef ?? f.host;
    if (!asset) continue;
    const cur = assetCounts.get(asset) ?? { findings: 0, worst: 99 };
    cur.findings++;
    cur.worst = Math.min(cur.worst, SEVERITY_ORDER.indexOf(f.severity));
    assetCounts.set(asset, cur);
  }
  const topAffectedAssets = [...assetCounts.entries()]
    .map(([asset, v]) => ({ asset, findings: v.findings, worstSeverity: SEVERITY_ORDER[v.worst] ?? "INFORMATIONAL" }))
    .sort((a, b) => b.findings - a.findings)
    .slice(0, 10);

  const openScores = findings.filter((f) => f.lifecycleStatus !== "RESOLVED" && f.lifecycleStatus !== "FALSE_POSITIVE").map((f) => f.riskScore ?? 0);
  const overallRiskScore = openScores.length ? Math.round(openScores.reduce((a, b) => a + b, 0) / openScores.length) : null;

  const isEmpty = findings.length === 0;
  const keyRecommendations: string[] = [];
  if (kevFindings > 0) keyRecommendations.push(`Remediate the ${kevFindings} KEV-listed finding(s) first — known-exploited vulnerabilities.`);
  if ((bySeverity.CRITICAL ?? 0) > 0) keyRecommendations.push(`Address ${bySeverity.CRITICAL} critical finding(s) within the SLA window.`);
  if (slaOverdue > 0) keyRecommendations.push(`${slaOverdue} finding(s) are past their remediation SLA — escalate ownership.`);
  if (isEmpty) keyRecommendations.push("No findings in scope for this period — maintain current assessment cadence.");

  const classification = input.classification ?? input.template?.classification ?? DEFAULT_REPORT_CLASSIFICATION;
  const sections = input.template?.sections?.length ? input.template.sections : [...REPORT_SECTION_CATALOG];

  const document: ReportSnapshotDocument = {
    reportId: input.reportId,
    title: sanitizeImportedText(input.title, 300),
    type: input.type,
    classification,
    ...(input.template?.organizationName ? { organizationName: input.template.organizationName } : {}),
    generatedAt: input.generatedAt.toISOString(),
    generatedBy: input.generatedBy,
    version: input.version,
    ...(input.period ? { period: input.period } : {}),
    scopeNote: domains.length === 0 ? "All security domains" : `Domains: ${domains.join(", ")}`,
    isEmpty,
    executiveSummary: {
      overallRiskScore,
      totalFindings: findings.length,
      bySeverity,
      criticalAndHigh: (bySeverity.CRITICAL ?? 0) + (bySeverity.HIGH ?? 0),
      kevFindings,
      internetFacingFindings: internetFacing,
      verifiedFindings,
      slaOverdue,
      topAffectedAssets,
      keyRecommendations,
      note: isEmpty
        ? "No data in scope: no stored findings matched this report's scope for the period. This is reported honestly rather than filled with placeholder statistics."
        : "All figures are computed from the stored canonical findings in scope at generation time; the snapshot is immutable (§56).",
    },
    findings,
    sections,
    severityDefinitions: input.template?.severityDefinitions ?? {},
    ...(input.template?.footer ? { footer: input.template.footer } : {}),
    customBlocks: (input.template?.customBlocks ?? []).map((b) => ({ title: sanitizeImportedText(b.title, 200), text: sanitizeImportedText(b.text, 4_000) })),
    watermark: `${classification} · Report ${input.reportId} · ${input.version}${input.template?.organizationName ? ` · ${input.template.organizationName}` : ""}`,
  };

  const contentHash = createHash("sha256").update(JSON.stringify(document)).digest("hex");
  return { document, contentHash };
}

/** §61/§62 shared text body used by the HTML/PDF renderers. */
export function snapshotToTextLines(doc: ReportSnapshotDocument): string[] {
  const lines: string[] = [];
  const push = (s = "") => lines.push(s);
  push(doc.title);
  push(`Classification: ${doc.classification}`);
  push(`Report ID: ${doc.reportId} · Version: ${doc.version} · Generated: ${doc.generatedAt} by ${doc.generatedBy}`);
  if (doc.organizationName) push(`Organization: ${doc.organizationName}`);
  if (doc.period?.start || doc.period?.end) push(`Reporting period: ${doc.period?.start ?? "…"} → ${doc.period?.end ?? "…"}`);
  push(`Scope: ${doc.scopeNote}`);
  push("");
  push("EXECUTIVE SUMMARY");
  push(doc.executiveSummary.note);
  push(`Total findings in scope: ${doc.executiveSummary.totalFindings}`);
  push(`Overall risk score (mean of open findings): ${doc.executiveSummary.overallRiskScore ?? "—"}`);
  push(`Critical + High: ${doc.executiveSummary.criticalAndHigh} · KEV: ${doc.executiveSummary.kevFindings} · Verified: ${doc.executiveSummary.verifiedFindings} · SLA overdue: ${doc.executiveSummary.slaOverdue}`);
  for (const sev of SEVERITY_ORDER) if (doc.executiveSummary.bySeverity[sev]) push(`  ${sev}: ${doc.executiveSummary.bySeverity[sev]}`);
  if (doc.executiveSummary.topAffectedAssets.length) {
    push("Top affected assets:");
    for (const a of doc.executiveSummary.topAffectedAssets) push(`  - ${a.asset} — ${a.findings} finding(s), worst ${a.worstSeverity}`);
  }
  push("Key recommendations:");
  for (const r of doc.executiveSummary.keyRecommendations) push(`  - ${r}`);
  push("");
  push("METHODOLOGY");
  push("Findings are canonical records produced by governed scanners and connectors, normalized, deduplicated by fingerprint and correlated across domains. Severities and risk scores are the platform's stored values; evidence is sanitized and redacted before inclusion.");
  push("");
  push("DETAILED FINDINGS");
  if (doc.isEmpty) push("No findings in scope for this report.");
  for (const f of doc.findings) {
    push("");
    push(`[${f.severity}] ${f.title} (${f.id})`);
    push(`Priority: ${f.priority ?? "—"} · Risk: ${f.riskScore ?? "—"} · Verification: ${f.verificationStatus} · Status: ${f.lifecycleStatus}`);
    if (f.cve || f.cwe || f.cvssScore !== undefined || f.epssScore !== undefined || f.kevListed) {
      push(`CVE: ${f.cve ?? "—"} · CWE: ${f.cwe ?? "—"} · CVSS: ${f.cvssScore ?? "—"} · EPSS: ${f.epssScore ?? "—"} · KEV: ${f.kevListed ? "yes" : "no"}`);
    }
    if (f.host || f.endpoint || f.assetRef) push(`Affected: ${f.assetRef ?? f.host ?? ""}${f.endpoint ? ` ${f.endpoint}` : ""}`);
    push(`Description: ${f.description}`);
    if (f.evidenceSummaries?.length) { push("Evidence (sanitized):"); for (const e of f.evidenceSummaries) push(`  - ${e}`); }
    if (f.evidenceFingerprints?.length) push(`Evidence fingerprints: ${f.evidenceFingerprints.join(", ")}`);
    if (f.sources?.length) push(`Sources: ${f.sources.join(", ")}`);
    if (f.remediation) push(`Remediation: ${f.remediation}`);
    if (f.references?.length) push(`References: ${f.references.map((r) => `${r.label} ${r.url}`).join("; ")}`);
    if (f.retestStatus) push(`Retest status: ${f.retestStatus}`);
  }
  if (doc.customBlocks.length) {
    push("");
    for (const b of doc.customBlocks) { push(b.title); push(b.text); push(""); }
  }
  if (doc.footer) { push(""); push(doc.footer); }
  push("");
  push(`— ${doc.watermark} —`);
  return lines;
}

export { escapeHtml };
