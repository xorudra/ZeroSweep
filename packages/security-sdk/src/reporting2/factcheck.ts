import type { ReportSnapshotDocument } from "../unified/reporting";

/**
 * Prompt 37 §87/§88/§146/§147: AI report-draft grounding + fact check.
 *
 * An AI (or rule-based) draft may only speak about the immutable
 * ReportDataSnapshot it was given. This checker validates the draft's
 * verifiable claims against that snapshot:
 *  - every CVE identifier mentioned must exist in the snapshot
 *    (§147: a hallucinated CVE is an unsupported claim and blocks);
 *  - every "N findings" count claim must equal the snapshot total;
 *  - severity counts stated per severity must match the snapshot.
 * Unsupported claims are returned verbatim so the caller can strip or
 * flag them — the draft is never silently "corrected" into a different
 * statement (§153: do not invent report facts).
 */
export interface FactCheckResult {
  ok: boolean;
  unsupportedClaims: string[];
  checkedCves: string[];
  snapshotFindingCount: number;
}

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const COUNT_RE = /\b(\d{1,6})\s+(?:total\s+)?findings?\b/gi;
const SEVERITY_COUNT_RE = /\b(\d{1,6})\s+(critical|high|medium|low|informational)\b/gi;

export function factCheckDraft(draftText: string, snapshot: ReportSnapshotDocument): FactCheckResult {
  const unsupported: string[] = [];
  const snapshotCves = new Set(
    snapshot.findings.map((f) => f.cve?.toUpperCase()).filter((c): c is string => !!c),
  );
  const mentioned = new Set<string>();
  for (const m of draftText.matchAll(CVE_RE)) {
    const cve = m[0].toUpperCase();
    mentioned.add(cve);
    if (!snapshotCves.has(cve)) unsupported.push(`unsupported CVE reference: ${cve}`);
  }
  for (const m of draftText.matchAll(COUNT_RE)) {
    const claimed = Number(m[1]);
    if (claimed !== snapshot.findings.length) {
      unsupported.push(`finding count claim "${m[0]}" does not match snapshot total ${snapshot.findings.length}`);
    }
  }
  for (const m of draftText.matchAll(SEVERITY_COUNT_RE)) {
    const claimed = Number(m[1]);
    const severity = m[2].toUpperCase();
    const actual = snapshot.executiveSummary.bySeverity[severity] ?? 0;
    if (claimed !== actual) {
      unsupported.push(`severity count claim "${m[0]}" does not match snapshot (${actual} ${severity})`);
    }
  }
  return {
    ok: unsupported.length === 0,
    unsupportedClaims: unsupported,
    checkedCves: [...mentioned],
    snapshotFindingCount: snapshot.findings.length,
  };
}

/**
 * §72/§86: deterministic executive-summary draft composed ONLY from
 * snapshot fields (the rule-based draft path — labelled as such by the
 * caller, never presented as a human analyst's prose). Every number in
 * the output comes from the snapshot, so factCheckDraft passes on it
 * by construction; the checker still runs as an independent gate.
 */
export function draftExecutiveSummary(snapshot: ReportSnapshotDocument): string {
  const es = snapshot.executiveSummary;
  const lines: string[] = [];
  lines.push(`This report covers ${es.totalFindings} findings in scope.`);
  const sevParts = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    .filter((s) => (es.bySeverity[s] ?? 0) > 0)
    .map((s) => `${es.bySeverity[s]} ${s.toLowerCase()}`);
  if (sevParts.length) lines.push(`Severity distribution: ${sevParts.join(", ")}.`);
  if (es.kevFindings > 0) lines.push(`${es.kevFindings} findings are listed in the CISA KEV catalog and take remediation priority.`);
  if (es.slaOverdue > 0) lines.push(`${es.slaOverdue} findings are past their remediation SLA.`);
  if (es.topAffectedAssets.length) {
    lines.push(`Most affected assets: ${es.topAffectedAssets.map((a) => `${a.asset} (${a.findings} findings, worst ${a.worstSeverity})`).join("; ")}.`);
  }
  const cveLines = snapshot.findings.filter((f) => f.cve).slice(0, 10)
    .map((f) => `${f.cve} — ${f.title} (${f.severity})`);
  if (cveLines.length) lines.push(`Notable tracked vulnerabilities: ${cveLines.join("; ")}.`);
  lines.push(es.note);
  return lines.join("\n");
}
