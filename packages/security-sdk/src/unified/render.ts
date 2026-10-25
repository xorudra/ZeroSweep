import { csvSafeCell } from "../vuln/redact";
import { escapeHtml } from "./sanitize";
import { snapshotToTextLines, type ReportSnapshotDocument } from "./reporting";
import { renderPdf } from "./pdf";

/**
 * Snapshot renderers (Prompt 20 §59/§69/§93). Every format renders the
 * SAME immutable snapshot document, so a PDF and a CSV of one report
 * version can never disagree. HTML output escapes every interpolated
 * value (§69/§110) — imported content was already sanitized at
 * snapshot-build time; this is the second, rendering-side barrier.
 */

export function renderReportJson(doc: ReportSnapshotDocument): string {
  return JSON.stringify(doc, null, 2);
}

export function renderReportHtml(doc: ReportSnapshotDocument): string {
  const sevRows = Object.entries(doc.executiveSummary.bySeverity)
    .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`)
    .join("");
  const findingBlocks = doc.isEmpty
    ? `<p><em>No findings in scope for this report.</em></p>`
    : doc.findings.map((f) => `
      <article class="finding">
        <h3>[${escapeHtml(f.severity)}] ${escapeHtml(f.title)}</h3>
        <p class="meta">ID ${escapeHtml(f.id)} · Priority ${escapeHtml(f.priority ?? "—")} · Risk ${f.riskScore ?? "—"} · ${escapeHtml(f.verificationStatus)} · ${escapeHtml(f.lifecycleStatus)}</p>
        ${f.cve || f.cwe ? `<p class="meta">CVE: ${escapeHtml(f.cve ?? "—")} · CWE: ${escapeHtml(f.cwe ?? "—")} · CVSS: ${f.cvssScore ?? "—"} · EPSS: ${f.epssScore ?? "—"} · KEV: ${f.kevListed ? "yes" : "no"}</p>` : ""}
        <p>${escapeHtml(f.description)}</p>
        ${(f.evidenceSummaries ?? []).length ? `<p><strong>Evidence (sanitized):</strong></p><ul>${f.evidenceSummaries!.map((e) => `<li>${escapeHtml(e)}</li>`).join("")}</ul>` : ""}
        ${f.remediation ? `<p><strong>Remediation:</strong> ${escapeHtml(f.remediation)}</p>` : ""}
      </article>`).join("");
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(doc.title)}</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#111}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.3rem .6rem}.meta{color:#555;font-size:.9em}.finding{border-top:1px solid #ddd;padding:.5rem 0}.wm{color:#777;font-size:.85em}</style>
</head><body>
<header>
<h1>${escapeHtml(doc.title)}</h1>
<p class="meta">Classification: ${escapeHtml(doc.classification)} · Report ${escapeHtml(doc.reportId)} · Version ${escapeHtml(doc.version)} · Generated ${escapeHtml(doc.generatedAt)} by ${escapeHtml(doc.generatedBy)}</p>
${doc.organizationName ? `<p class="meta">Organization: ${escapeHtml(doc.organizationName)}</p>` : ""}
<p class="meta">Scope: ${escapeHtml(doc.scopeNote)}</p>
</header>
<section><h2>Executive summary</h2>
<p>${escapeHtml(doc.executiveSummary.note)}</p>
<p>Total findings: ${doc.executiveSummary.totalFindings} · Critical+High: ${doc.executiveSummary.criticalAndHigh} · KEV: ${doc.executiveSummary.kevFindings} · Verified: ${doc.executiveSummary.verifiedFindings} · SLA overdue: ${doc.executiveSummary.slaOverdue} · Overall risk: ${doc.executiveSummary.overallRiskScore ?? "—"}</p>
<table><tr><th>Severity</th><th>Count</th></tr>${sevRows}</table>
<h3>Key recommendations</h3><ul>${doc.executiveSummary.keyRecommendations.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>
</section>
<section><h2>Detailed findings</h2>${findingBlocks}</section>
${doc.customBlocks.map((b) => `<section><h2>${escapeHtml(b.title)}</h2><p>${escapeHtml(b.text)}</p></section>`).join("")}
${doc.footer ? `<footer><p>${escapeHtml(doc.footer)}</p></footer>` : ""}
<p class="wm">— ${escapeHtml(doc.watermark)} —</p>
</body></html>`;
}

const CSV_HEADER = ["id", "title", "severity", "priority", "riskScore", "verificationStatus", "lifecycleStatus", "sourceDomain", "category", "cve", "cwe", "cvss", "epss", "kev", "host", "endpoint", "firstSeen", "sources", "evidenceFingerprints"];

/** §93: streaming-friendly CSV — one row at a time, bounded memory. */
export function* csvRowGenerator(doc: ReportSnapshotDocument): Generator<string> {
  yield CSV_HEADER.join(",") + "\n";
  for (const f of doc.findings) {
    const cells = [
      f.id, f.title, f.severity, f.priority ?? "", f.riskScore ?? "", f.verificationStatus, f.lifecycleStatus,
      f.sourceDomain ?? "", f.category ?? "", f.cve ?? "", f.cwe ?? "", f.cvssScore ?? "", f.epssScore ?? "",
      f.kevListed ? "yes" : "no", f.host ?? "", f.endpoint ?? "", f.firstSeen,
      (f.sources ?? []).join(";"), (f.evidenceFingerprints ?? []).join(";"),
    ].map((c) => {
      const safe = csvSafeCell(String(c));
      return /[",\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
    });
    yield cells.join(",") + "\n";
  }
}

export function renderReportCsv(doc: ReportSnapshotDocument): string {
  return [...csvRowGenerator(doc)].join("");
}

export function renderReportPdf(doc: ReportSnapshotDocument): Buffer {
  return renderPdf({
    title: doc.title,
    creator: "ZeroSweep ReportingEngine",
    lines: snapshotToTextLines(doc),
    footer: doc.watermark,
  });
}

export type ReportFormat = "PDF" | "HTML" | "JSON" | "CSV";

export function renderReport(doc: ReportSnapshotDocument, format: ReportFormat): { content: string; contentType: string } | { content: Buffer; contentType: string } {
  switch (format) {
    case "JSON": return { content: renderReportJson(doc), contentType: "application/json" };
    case "HTML": return { content: renderReportHtml(doc), contentType: "text/html" };
    case "CSV": return { content: renderReportCsv(doc), contentType: "text/csv" };
    case "PDF": return { content: renderReportPdf(doc), contentType: "application/pdf" };
  }
}
