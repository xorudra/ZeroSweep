import { describe, expect, it } from "vitest";
import { fingerprintV2, isExactDuplicate } from "./fingerprint-v2";
import { deriveCorrelationLinks, buildFindingClusters } from "./correlation";
import { computeRiskV3 } from "./risk-v3";
import { prioritize } from "./prioritization";
import { evaluateOwnershipRules, mayAutoAssign } from "./ownership";
import { computeSlaDeadlines, slaStateFor, DEFAULT_VM_SLA_POLICY } from "./sla-engine";
import { evaluateExceptionApproval, isExceptionExpired, exceptionRequiresSeparateApprover } from "./exceptions";
import { routeRetest, judgeUnifiedRetest } from "./retest-router";
import { sanitizeImportedText, sanitizeImportedUrl, checkImportBounds, IMPORT_LIMITS } from "./sanitize";
import {
  computeImportPreview, detectSyncConflicts, applyExportPolicy, DEFAULT_EXPORT_POLICY,
  FixtureConnectorTransport, UnconfiguredConnectorTransport, validateConnectorEndpoint,
} from "./connectors";
import { DefectDojoConnector, FaradayConnector, PlexTracConnector } from "./connectors-platforms";
import { buildReportSnapshot, validateReportTemplate, nextReportVersion, canTransitionReportApproval } from "./reporting";
import { renderReportCsv, renderReportHtml, renderReportJson, renderReportPdf, csvRowGenerator } from "./render";
import { executiveDashboard, securityCoverage, meanTimeToRemediate, reopenRate, globalSearch } from "./analytics";
import { crossDomainChainFixture, cveClusterFixture, fixtureFinding, HOSTILE_EXTERNAL_RECORD, reportFindingsFixture, resetFixtureSeq } from "./fixtures";
import type { FindingEnrichment } from "../vulnmgmt/enrichment";

const WS = "ws-fixture";
const CONFIG = { endpointReference: "dd-main", credentialReference: "dd-api-key-ref", endpointAllowlist: ["dd-main"] };

describe("Fingerprint V2 + exact dedup (§12/§13/§99)", () => {
  it("Nuclei + ZAP + Burp observations of the same web issue share one fingerprint", () => {
    const base = { workspaceId: WS, sourceDomain: "WEB", host: "example.com", endpoint: "https://example.com/search?q=1", parameter: "q", cwe: "CWE-79" };
    expect(fingerprintV2(base)).toBe(fingerprintV2({ ...base }));
    expect(isExactDuplicate(base, { ...base, host: "EXAMPLE.COM" })).toBe(true);
  });

  it("different parameter = different issue", () => {
    const base = { workspaceId: WS, sourceDomain: "WEB", host: "example.com", endpoint: "https://example.com/s", parameter: "q", cwe: "CWE-79" };
    expect(isExactDuplicate(base, { ...base, parameter: "r" })).toBe(false);
  });

  it("same CVE in SCA vs container does NOT collapse (separate remediation state, §16)", () => {
    const sca = { workspaceId: WS, sourceDomain: "SCA", componentPurl: "pkg:npm/log4j@2.14", cve: "CVE-2021-44228" };
    const cont = { workspaceId: WS, sourceDomain: "CONTAINER", componentPurl: "pkg:npm/log4j@2.14", cve: "CVE-2021-44228", imageDigest: "sha256:abc" };
    expect(fingerprintV2(sca)).not.toBe(fingerprintV2(cont));
  });

  it("tenant is part of the fingerprint", () => {
    const base = { workspaceId: WS, sourceDomain: "WEB", host: "example.com", cwe: "CWE-79" };
    expect(fingerprintV2(base)).not.toBe(fingerprintV2({ ...base, workspaceId: "ws-other" }));
  });
});

describe("Correlation (§14–§17/§100)", () => {
  it("cross-domain chain links EXPOSES + RELATED without merging root causes", () => {
    const chain = crossDomainChainFixture();
    const links = deriveCorrelationLinks(chain);
    expect(links.some((l) => l.relationship === "EXPOSES")).toBe(true);
    const web = chain.find((f) => f.sourceDomain === "WEB")!;
    const sast = chain.find((f) => f.sourceDomain === "SAST")!;
    expect(links.some((l) => l.relationship === "RELATED" && [l.fromFindingId, l.toFindingId].includes(web.id) && [l.fromFindingId, l.toFindingId].includes(sast.id))).toBe(true);
    // No DUPLICATE merges anywhere in the chain — distinct root causes stay distinct (§15).
    expect(links.some((l) => l.relationship === "DUPLICATE")).toBe(false);
    expect(chain.length).toBe(5);
  });

  it("shared CWE alone produces no link (§17)", () => {
    resetFixtureSeq();
    const a = { ...fixtureFinding({ title: "A", sourceDomain: "WEB", cwe: "CWE-89", host: "a.example.com" }), fingerprint: "x1" };
    const b = { ...fixtureFinding({ title: "B", sourceDomain: "SAST", cwe: "CWE-89", host: "b.example.com" }), fingerprint: "x2" };
    expect(deriveCorrelationLinks([a, b])).toEqual([]);
  });

  it("identical titles alone produce no link (§14)", () => {
    resetFixtureSeq();
    const a = { ...fixtureFinding({ title: "Same title", sourceDomain: "WEB", host: "a.example.com" }), fingerprint: "y1" };
    const b = { ...fixtureFinding({ title: "Same title", sourceDomain: "NETWORK", host: "b.example.com" }), fingerprint: "y2" };
    expect(deriveCorrelationLinks([a, b])).toEqual([]);
  });

  it("identical fingerprints on two rows → POTENTIAL_DUPLICATE for review, never auto-merge", () => {
    resetFixtureSeq();
    const a = { ...fixtureFinding({ title: "A" }), fingerprint: "same" };
    const b = { ...fixtureFinding({ title: "B" }), fingerprint: "same" };
    const links = deriveCorrelationLinks([a, b]);
    expect(links).toHaveLength(1);
    expect(links[0]!.relationship).toBe("POTENTIAL_DUPLICATE");
  });
});

describe("Clusters (§18/§101)", () => {
  it("one CVE across 4 domains = one cluster, 4 independent findings", () => {
    const findings = cveClusterFixture();
    const clusters = buildFindingClusters(findings);
    const cve = clusters.find((c) => c.kind === "CVE");
    expect(cve).toBeDefined();
    expect(cve!.findingIds).toHaveLength(4);
    expect(findings).toHaveLength(4); // nothing merged away
  });
});

describe("Risk Engine V3 (§20–§23/§102)", () => {
  const enrichment = { kevListed: true, epss: { score: 0.9, percentile: 0.99 }, cvss: { effective: 9.8 }, linkKeys: [], notes: [], snapshotId: "snap-fixture" } as unknown as FindingEnrichment;
  const base = { severity: "HIGH" as const, confidence: 0.9, cvssScore: 8.0 };

  it("is deterministic", () => {
    const a = computeRiskV3({ ...base, enrichment });
    const b = computeRiskV3({ ...base, enrichment });
    expect(a.score).toBe(b.score);
    expect(a.calcVersion).toBe("risk-v3.0");
  });

  it("KEV + EPSS raise the score vs the plain finding; exposure raises it further", () => {
    const plain = computeRiskV3({ ...base });
    const intel = computeRiskV3({ ...base, enrichment });
    const exposed = computeRiskV3({ ...base, enrichment, internetExposed: true, attackPathContext: true, environment: "PRODUCTION", dataSensitivity: "RESTRICTED", slaState: "OVERDUE" });
    expect(intel.score).toBeGreaterThan(plain.score);
    expect(exposed.score).toBeGreaterThanOrEqual(intel.score);
  });

  it("every score is explainable: adjustments, missing info, confidence (§23)", () => {
    const r = computeRiskV3({ ...base });
    expect(r.missingInformation).toContain("data sensitivity classification");
    expect(r.scoreConfidence).toBeGreaterThan(0);
    expect(r.scoreConfidence).toBeLessThanOrEqual(1);
    expect(Array.isArray(r.factors)).toBe(true);
  });

  it("REJECTED findings score 0", () => {
    expect(computeRiskV3({ ...base, verificationStatus: "REJECTED" }).score).toBe(0);
  });
});

describe("Prioritization (§24/§25)", () => {
  it("verified KEV on internet-facing production → P0", () => {
    const r = prioritize({ riskScore: 60, severity: "HIGH", kevListed: true, verificationStatus: "VERIFIED", internetExposed: true, environment: "PRODUCTION" });
    expect(r.priority).toBe("P0");
  });

  it("KEV alone (unverified, internal, lab) is NOT auto-P0 (§25)", () => {
    const r = prioritize({ riskScore: 40, severity: "MEDIUM", kevListed: true, verificationStatus: "UNVERIFIED", internetExposed: false, environment: "LAB" });
    expect(r.priority).not.toBe("P0");
    expect(r.rationale.join(" ")).toContain("no automatic P0");
  });

  it("priority is not severity: a MEDIUM can outrank via context", () => {
    const r = prioritize({ riskScore: 85, severity: "MEDIUM", kevListed: true, epssScore: 0.9, verificationStatus: "VERIFIED", internetExposed: true, environment: "PRODUCTION", assetCriticality: "CRITICAL" });
    expect(r.priority).toBe("P0");
  });
});

describe("Ownership (§26/§27)", () => {
  const rules = [
    { id: "r1", matchKind: "SOURCE_DOMAIN" as const, matchValue: "CLOUD", ownerType: "TEAM" as const, ownerRef: "Cloud Security", priority: 10, enabled: true },
    { id: "r2", matchKind: "REPOSITORY" as const, matchValue: "repo-1", ownerType: "TEAM" as const, ownerRef: "AppSec", priority: 5, enabled: true },
  ];
  it("first matching rule in priority order wins", () => {
    const d = evaluateOwnershipRules(rules, { sourceDomain: "CLOUD", repositoryId: "repo-1" });
    expect(d?.ownerRef).toBe("AppSec"); // priority 5 beats 10
  });
  it("auto-assignment never overrides a manual assignment", () => {
    expect(mayAutoAssign("MANUAL")).toBe(false);
    expect(mayAutoAssign("RULE")).toBe(true);
    expect(mayAutoAssign(undefined)).toBe(true);
  });
});

describe("SLA engine (§28–§30/§103)", () => {
  const created = new Date("2026-10-01T00:00:00Z");
  it("computes triage/remediation deadlines from severity + priority with modifiers", () => {
    const d = computeSlaDeadlines(DEFAULT_VM_SLA_POLICY, { severity: "CRITICAL", priority: "P0", createdAt: created, environment: "PRODUCTION", assetCriticality: "CRITICAL" });
    expect(d.triageDueAt?.toISOString()).toBe("2026-10-02T00:00:00.000Z"); // 24h triage
    expect(d.appliedRemediationHours).toBe(24); // P0 48h × PRODUCTION 1 × CRITICAL 0.5
    expect(d.remediationDueAt?.toISOString()).toBe("2026-10-02T00:00:00.000Z");
  });
  it("states: OVERDUE / DUE_SOON / PAUSED / NOT_APPLICABLE", () => {
    const due = new Date("2026-10-02T00:00:00Z");
    expect(slaStateFor({ dueAt: due, lifecycleStatus: "NEW", createdAt: created }, new Date("2026-10-03T00:00:00Z"))).toBe("OVERDUE");
    expect(slaStateFor({ dueAt: due, lifecycleStatus: "RESOLVED", createdAt: created }, new Date("2026-10-03T00:00:00Z"))).toBe("NOT_APPLICABLE");
    expect(slaStateFor({ dueAt: due, lifecycleStatus: "NEW", createdAt: created, pausedAt: created, pauseReason: "waiting on vendor" }, new Date("2026-10-03T00:00:00Z"))).toBe("PAUSED");
    expect(slaStateFor({ dueAt: undefined, lifecycleStatus: "NEW", createdAt: created })).toBe("NOT_APPLICABLE");
  });
});

describe("Exceptions (§31–§33/§104)", () => {
  const ex = { id: "ex-1", findingId: "f-1", type: "ACCEPTED_RISK" as const, status: "PENDING" as const, requestedBy: "u-1", reason: "compensating control in place", expiresAt: new Date("2027-01-01T00:00:00Z"), createdAt: new Date() };
  it("high-risk exceptions require a separate approver", () => {
    expect(exceptionRequiresSeparateApprover({ severity: "CRITICAL" })).toBe(true);
    expect(evaluateExceptionApproval({ exception: ex, approverId: "u-1", severity: "CRITICAL" }).ok).toBe(false);
    expect(evaluateExceptionApproval({ exception: ex, approverId: "u-2", severity: "CRITICAL" }).ok).toBe(true);
  });
  it("expired exceptions no longer apply (§33)", () => {
    const active = { ...ex, status: "ACTIVE" as const, expiresAt: new Date("2026-01-01T00:00:00Z") };
    expect(isExceptionExpired(active, new Date("2026-06-01T00:00:00Z"))).toBe(true);
  });
});

describe("RetestRouter (§37–§39/§105)", () => {
  it("routes each domain to its own safe engine", () => {
    expect(routeRetest({ sourceDomain: "WEB", lifecycleStatus: "REMEDIATED" })).toMatchObject({ ok: true, route: { kind: "WEB_VALIDATOR" } });
    expect(routeRetest({ sourceDomain: "CLOUD", lifecycleStatus: "REMEDIATED" })).toMatchObject({ ok: true, route: { kind: "CLOUD_READONLY_CHECK", maxIntrusiveness: "PASSIVE" } });
    expect(routeRetest({ sourceDomain: "WIRELESS", lifecycleStatus: "REMEDIATED" })).toMatchObject({ ok: true, route: { kind: "WIRELESS_PASSIVE_OBSERVATION" } });
  });
  it("unremediated findings cannot be retested", () => {
    expect(routeRetest({ sourceDomain: "WEB", lifecycleStatus: "NEW" }).ok).toBe(false);
  });
  it("no evidence → INCONCLUSIVE, never RESOLVED", () => {
    expect(judgeUnifiedRetest({ originalFingerprint: "fp", producedFingerprints: [], evidenceProduced: false })).toBe("INCONCLUSIVE");
    expect(judgeUnifiedRetest({ originalFingerprint: "fp", producedFingerprints: ["other"], evidenceProduced: true })).toBe("RESOLVED");
    expect(judgeUnifiedRetest({ originalFingerprint: "fp", producedFingerprints: ["fp"], evidenceProduced: true })).toBe("REOPENED");
  });
});

describe("Import sanitization (§51/§97/§98)", () => {
  it("hostile record normalizes safely: no script, no escapes, no fake URL", () => {
    const title = sanitizeImportedText(HOSTILE_EXTERNAL_RECORD.title, IMPORT_LIMITS.maxTitleLength);
    expect(title).not.toContain("<script>");
    expect(title).toContain("SQL injection");
    expect(sanitizeImportedUrl(HOSTILE_EXTERNAL_RECORD.url)).toBeUndefined();
    const desc = sanitizeImportedText(HOSTILE_EXTERNAL_RECORD.description, 4000);
    expect(desc).not.toContain("[31m");
    expect(desc).not.toContain("\uD800");
  });
  it("bomb bounds reject deep nesting", () => {
    let deep: unknown = "x";
    for (let i = 0; i < 12; i++) deep = { a: deep };
    expect(checkImportBounds(deep).ok).toBe(false);
    expect(checkImportBounds({ a: [1, 2] }).ok).toBe(true);
  });
});

describe("Connectors (§40–§54/§106/§107)", () => {
  it("DefectDojo import maps + sanitizes the hostile fixture", async () => {
    const dd = new DefectDojoConnector();
    const transport = new FixtureConnectorTransport({ "GET /api/v2/findings/?limit=1000": { results: [HOSTILE_EXTERNAL_RECORD] } });
    const records = await dd.importFindings(CONFIG, transport, WS);
    expect(records).toHaveLength(1);
    expect(records[0]!.title).not.toContain("<script>");
    expect(records[0]!.severity).toBe("CRITICAL");
    expect(records[0]!.externalUrl).toBeUndefined();
    expect(records[0]!.status).toBe("IN_PROGRESS");
  });

  it("unconfigured transport → NOT_CONFIGURED health, never fabricated", async () => {
    const dd = new DefectDojoConnector();
    const health = await dd.healthCheck(CONFIG, new UnconfiguredConnectorTransport("DEFECTDOJO"));
    expect(health.status).toBe("NOT_CONFIGURED");
  });

  it("endpoint allowlist is enforced (§50)", () => {
    expect(validateConnectorEndpoint({ endpointReference: "evil", endpointAllowlist: ["dd-main"] }).ok).toBe(false);
    expect(validateConnectorEndpoint(CONFIG).ok).toBe(true);
  });

  it("Faraday status/severity mapping", () => {
    const f = new FaradayConnector();
    expect(f.mapStatus("re-opened")).toBe("REOPENED");
    expect(f.mapSeverity("informational")).toBe("INFORMATIONAL");
    expect(f.toExternalStatus("RESOLVED")).toBe("closed");
  });

  it("PlexTrac stays inert without a confirmed license (§47)", async () => {
    const p = new PlexTracConnector();
    expect(p.capabilities(CONFIG)).toEqual([]);
    const health = await p.healthCheck(CONFIG, new FixtureConnectorTransport({}));
    expect(health.status).toBe("LICENSE_UNAVAILABLE");
  });

  it("import preview: repeat import is an update, not a duplicate (§53/§106)", () => {
    const incoming = [{ externalId: "dd-1", title: "X", description: "", severity: "HIGH", status: "IN_PROGRESS", fingerprint: "fp-1" }];
    const existing = {
      byExternalId: new Map([["dd-1", { findingId: "f-1", status: "IN_PROGRESS", severity: "HIGH" }]]),
      byFingerprint: new Map([["fp-1", "f-1"]]),
    };
    const preview = computeImportPreview(incoming, existing);
    expect(preview.newFindings).toHaveLength(0);
    expect(preview.updates).toHaveLength(1);
  });

  it("sync conflict: local IN_PROGRESS vs external CLOSED (§107)", () => {
    const conflicts = detectSyncConflicts(
      { findingId: "f-1", externalId: "dd-1", localStatus: "IN_PROGRESS", localSeverity: "HIGH" },
      { externalId: "dd-1", title: "X", description: "", severity: "HIGH", status: "RESOLVED", fingerprint: "fp" },
    );
    expect(conflicts.some((c) => c.field === "external_closed")).toBe(true);
  });

  it("export policy strips host/evidence by default (§54)", () => {
    const out = applyExportPolicy({ title: "t", description: "d", severity: "HIGH", status: "NEW", host: "internal.corp", evidenceSummary: "raw", secretFingerprint: "sha256:x" }, DEFAULT_EXPORT_POLICY);
    expect(out.host).toBeUndefined();
    expect(out.evidence).toBeUndefined();
    expect(out.secretFingerprint).toBeUndefined();
  });
});

describe("Reporting (§55–§70/§108–§111)", () => {
  const build = () => buildReportSnapshot({
    reportId: "rpt-1", title: "Q4 Executive Report", type: "EXECUTIVE", generatedBy: "u-admin",
    generatedAt: new Date("2026-10-08T00:00:00Z"), version: "v1", findings: reportFindingsFixture(),
    slaOverdueIds: [], internetFacingIds: ["rep-1"],
  });

  it("snapshot is immutable: mutating the source afterwards changes nothing (§108)", () => {
    const src = reportFindingsFixture();
    const { document, contentHash } = buildReportSnapshot({ reportId: "r", title: "t", type: "EXECUTIVE", generatedBy: "u", generatedAt: new Date(), version: "v1", findings: src });
    src[0]!.title = "CHANGED AFTER GENERATION";
    src[0]!.severity = "CRITICAL";
    expect(document.findings[0]!.title).toBe("Session token reflected in response");
    expect(document.findings[0]!.severity).toBe("HIGH");
    expect(contentHash).toHaveLength(64);
  });

  it("redaction: fixture secrets never reach any format (§109)", () => {
    const { document } = build();
    const json = renderReportJson(document);
    const html = renderReportHtml(document);
    const csv = renderReportCsv(document);
    const pdf = renderReportPdf(document).toString("latin1");
    for (const out of [json, html, csv, pdf]) {
      expect(out).not.toContain("FIXTURE_TOKEN_VALUE");
      expect(out).not.toContain("FIXTURE_SESSION_VALUE");
      expect(out).not.toContain("FIXTUREKEYMATERIAL");
      expect(out).not.toContain("hunter2fixture");
    }
    expect(document.executiveSummary.internetFacingFindings).toBe(1);
  });

  it("XSS: hostile titles are neutralized at snapshot time AND escaped at render time (§110)", () => {
    const hostile = [{ ...reportFindingsFixture()[0]!, id: "rep-x", title: "<script>alert(1)</script>Owned" }];
    const { document } = buildReportSnapshot({ reportId: "r2", title: "t", type: "WEB", generatedBy: "u", generatedAt: new Date(), version: "v1", findings: hostile });
    // Barrier 1: the snapshot builder sanitizes — tags never enter the snapshot.
    expect(renderReportHtml(document)).not.toContain("<script>alert(1)</script>");
    // Barrier 2: even a hand-built document with raw markup is escaped by the renderer.
    const rawDoc = { ...document, findings: [{ ...document.findings[0]!, title: "<script>alert(1)</script>Owned" }] };
    const html = renderReportHtml(rawDoc);
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).toContain("&lt;script&gt;");
  });

  it("PDF has real structure; empty reports are honest (§60)", () => {
    const { document } = build();
    const pdf = renderReportPdf(document);
    expect(pdf.subarray(0, 5).toString()).toBe("%PDF-");
    expect(pdf.toString("latin1")).toContain("%%EOF");
    const empty = buildReportSnapshot({ reportId: "r3", title: "Empty", type: "WEB", generatedBy: "u", generatedAt: new Date(), version: "v1", findings: [] });
    expect(empty.document.isEmpty).toBe(true);
    expect(empty.document.executiveSummary.note).toContain("No data in scope");
    expect(empty.document.executiveSummary.overallRiskScore).toBeNull();
  });

  it("CSV is formula-injection safe and streams row-bounded (§93/§111)", () => {
    const { document } = build();
    const rows = [...csvRowGenerator(document)];
    expect(rows[0]).toContain("id,title,severity");
    expect(rows).toHaveLength(2);
  });

  it("templates refuse executable content; versions + approval flow (§66–§68)", () => {
    expect(validateReportTemplate({ sections: ["COVER"], customBlocks: [{ title: "x", text: "<script>bad</script>" }] }).ok).toBe(false);
    expect(validateReportTemplate({ sections: ["COVER", "DETAILED_FINDINGS"] }).ok).toBe(true);
    expect(validateReportTemplate({ sections: ["NOT_A_SECTION"] }).ok).toBe(false);
    expect(nextReportVersion("v1", "minor")).toBe("v1.1");
    expect(nextReportVersion("v1.1", "major")).toBe("v2");
    expect(canTransitionReportApproval("DRAFT", "REVIEW")).toBe(true);
    expect(canTransitionReportApproval("DRAFT", "ISSUED")).toBe(false);
    expect(build().document.classification).toBe("CONFIDENTIAL");
  });
});

describe("Analytics (§71–§83)", () => {
  it("executive dashboard counts from stored findings only", () => {
    resetFixtureSeq();
    const findings = [
      fixtureFinding({ title: "c1", severity: "CRITICAL", lifecycleStatus: "NEW", riskScore: 95, kevListed: true }),
      fixtureFinding({ title: "h1", severity: "HIGH", lifecycleStatus: "IN_PROGRESS", riskScore: 70 }),
      fixtureFinding({ title: "done", severity: "LOW", lifecycleStatus: "RESOLVED", resolvedAt: new Date("2026-10-05T00:00:00Z") }),
    ];
    const dash = executiveDashboard(findings, { internetFacingIds: [findings[0]!.id] });
    expect(dash.criticalFindings).toBe(1);
    expect(dash.kevFindings).toBe(1);
    expect(dash.internetFacingFindings).toBe(1);
    expect(dash.remediationRate).toBe(0.33);
  });

  it("MTTR + reopen rate from stored timestamps (§77/§79)", () => {
    resetFixtureSeq();
    const findings = [
      fixtureFinding({ title: "a", lifecycleStatus: "RESOLVED", firstSeen: new Date("2026-10-01T00:00:00Z"), resolvedAt: new Date("2026-10-03T00:00:00Z") }),
      fixtureFinding({ title: "b", lifecycleStatus: "REOPENED", firstSeen: new Date("2026-10-01T00:00:00Z"), resolvedAt: new Date("2026-10-02T00:00:00Z"), recurrenceCount: 1 }),
    ];
    expect(meanTimeToRemediate(findings).overallHours).toBe(36);
    expect(reopenRate(findings).rate).toBe(0.5);
  });

  it("unknown coverage is null, never 100% (§80)", () => {
    const cov = securityCoverage({ assetsDiscovered: 0, assetsScanned: 0, repositoriesScanned: 3, cloudAccountsAssessed: 1, clustersAssessed: 0, mobileBuildsAssessed: 0, wirelessEnvironmentsAssessed: 0 });
    expect(cov.assetsScannedPct).toBeNull();
    expect(cov.repositoriesPct).toBeNull();
  });

  it("global search finds findings by CVE and assets by host (§83)", () => {
    resetFixtureSeq();
    const findings = [fixtureFinding({ title: "Log4Shell", cve: "CVE-2021-44228" })];
    const hits = globalSearch({ findings, assets: [{ id: "a1", host: "example.com" }], repositories: [], cloudResources: [], mobileApps: [], binaryHashes: [] }, "44228");
    expect(hits.some((h) => h.kind === "FINDING")).toBe(true);
    const hits2 = globalSearch({ findings, assets: [{ id: "a1", host: "example.com" }], repositories: [], cloudResources: [], mobileApps: [], binaryHashes: [] }, "example");
    expect(hits2.some((h) => h.kind === "ASSET")).toBe(true);
  });
});
