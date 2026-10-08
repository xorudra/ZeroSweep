import { describe, expect, it } from "vitest";
import {
  toV2LifecycleState, isV2Open, buildTriageQueue, triageScore,
  deriveSlaStatus, scanForSecrets, redactClientText, redactionPreview,
  factCheckDraft, draftExecutiveSummary, computeVulnerabilityMetrics,
  executiveTrendSeries, decideSyncRecord, syncContentHash,
  canonicalStatusFor, externalStatusFor, normalizeSyncSeverity,
} from "./index";
import { buildReportSnapshot } from "../unified/reporting";

const NOW = new Date("2026-10-08T00:00:00Z");

describe("V2 lifecycle view (§7/§8)", () => {
  it("derives the §7 vocabulary from the governed machines", () => {
    expect(toV2LifecycleState({ lifecycleStatus: "NEW" })).toBe("NEW");
    expect(toV2LifecycleState({ lifecycleStatus: "CONFIRMED" })).toBe("CONFIRMED");
    expect(toV2LifecycleState({ lifecycleStatus: "REMEDIATED" })).toBe("FIX_CLAIMED");
    expect(toV2LifecycleState({ lifecycleStatus: "RETEST_PENDING" })).toBe("VERIFICATION_PENDING");
    expect(toV2LifecycleState({ lifecycleStatus: "RESOLVED", caseVerificationState: "PASSED" })).toBe("FIXED_VERIFIED");
    expect(toV2LifecycleState({ lifecycleStatus: "RESOLVED" })).toBe("CLOSED");
    expect(toV2LifecycleState({ lifecycleStatus: "NEW", caseStatus: "PLANNED" })).toBe("REMEDIATION_PLANNED");
    expect(toV2LifecycleState({ lifecycleStatus: "IN_PROGRESS", caseStatus: "VERIFIED_FIXED" })).toBe("FIXED_VERIFIED");
    expect(isV2Open("FIX_CLAIMED")).toBe(true);
    expect(isV2Open("FIXED_VERIFIED")).toBe(false);
  });
});

describe("triage queue (§11)", () => {
  it("scores KEV + critical + exposed above a plain low and excludes terminal findings", () => {
    const queue = buildTriageQueue([
      { id: "low", severity: "LOW", lifecycleStatus: "NEW", createdAt: "2026-10-01T00:00:00Z" },
      { id: "hot", severity: "CRITICAL", lifecycleStatus: "NEW", kevListed: true, epssScore: 0.9, internetExposed: true, riskScore: 95, createdAt: "2026-09-01T00:00:00Z" },
      { id: "done", severity: "CRITICAL", lifecycleStatus: "RESOLVED", createdAt: "2026-09-01T00:00:00Z" },
    ], NOW);
    expect(queue.map((q) => q.findingId)).toEqual(["hot", "low"]);
    expect(queue[0]!.band).toBe("P0");
    expect(queue[0]!.factors.some((f) => f.key === "kev")).toBe(true);
  });
  it("is deterministic for equal scores (oldest first)", () => {
    const a = triageScore({ id: "a", severity: "HIGH", lifecycleStatus: "NEW", createdAt: "2026-10-01T00:00:00Z" }, NOW);
    const b = triageScore({ id: "b", severity: "HIGH", lifecycleStatus: "NEW", createdAt: "2026-10-02T00:00:00Z" }, NOW);
    expect(a.score).toBe(b.score);
  });
});

describe("SLA status (§25)", () => {
  it("derives OVERDUE / EXEMPT / VERIFICATION_PENDING / ON_TRACK", () => {
    expect(deriveSlaStatus({ dueAt: "2026-10-01T00:00:00Z", lifecycleStatus: "CONFIRMED", now: NOW })).toBe("OVERDUE");
    expect(deriveSlaStatus({ dueAt: "2026-10-01T00:00:00Z", lifecycleStatus: "CONFIRMED", now: NOW, hasActiveException: true })).toBe("EXEMPT");
    expect(deriveSlaStatus({ dueAt: "2027-10-01T00:00:00Z", lifecycleStatus: "REMEDIATED", now: NOW, verificationPending: true })).toBe("VERIFICATION_PENDING");
    expect(deriveSlaStatus({ dueAt: null, lifecycleStatus: "NEW", now: NOW })).toBe("ON_TRACK");
    expect(deriveSlaStatus({ dueAt: "2026-10-01T00:00:00Z", lifecycleStatus: "RESOLVED", now: NOW })).toBe("ON_TRACK");
  });
});

describe("redaction (§40/§90/§91/§142)", () => {
  const dirty = "password: hunter2\nCookie: session=abc123\n-----BEGIN RSA PRIVATE KEY-----\nMIIxyz\n-----END RSA PRIVATE KEY-----\nkey AKIAIOSFODNN7EXAMPLE contact admin@example.com";
  it("scans secret shapes without returning values", () => {
    const found = scanForSecrets(dirty);
    const kinds = found.map((f) => f.kind);
    expect(kinds).toContain("PASSWORD_ASSIGNMENT");
    expect(kinds).toContain("COOKIE");
    expect(kinds).toContain("PRIVATE_KEY");
    expect(kinds).toContain("AWS_KEY");
    expect(JSON.stringify(found)).not.toContain("hunter2");
  });
  it("redacts client text so planted secrets are absent", () => {
    const clean = redactClientText(dirty);
    for (const secret of ["hunter2", "abc123", "MIIxyz", "AKIAIOSFODNN7EXAMPLE", "admin@example.com"]) {
      expect(clean).not.toContain(secret);
    }
  });
  it("previews warnings by location over a document", () => {
    const preview = redactionPreview({ findings: [{ note: "token: abcdefgh" }], title: "clean" });
    expect(preview.clean).toBe(false);
    expect(preview.warnings[0]!.location).toBe("findings[0].note");
    expect(redactionPreview({ title: "nothing here" }).clean).toBe(true);
  });
});

describe("AI draft fact check (§88/§146/§147)", () => {
  const { document } = buildReportSnapshot({
    reportId: "r1", title: "T", type: "EXECUTIVE", generatedBy: "u1", generatedAt: NOW, version: "v1",
    findings: [
      { id: "f1", title: "SQL injection", description: "d", severity: "CRITICAL", verificationStatus: "CONFIRMED", lifecycleStatus: "CONFIRMED", cve: "CVE-2024-12345", firstSeen: "2026-10-01T00:00:00.000Z" },
      { id: "f2", title: "XSS", description: "d", severity: "HIGH", verificationStatus: "UNVERIFIED", lifecycleStatus: "NEW", firstSeen: "2026-10-01T00:00:00.000Z" },
    ],
  });
  it("accepts a grounded draft and the deterministic summary passes its own gate", () => {
    const draft = draftExecutiveSummary(document);
    expect(factCheckDraft(draft, document).ok).toBe(true);
    expect(factCheckDraft("This report covers 2 findings including CVE-2024-12345.", document).ok).toBe(true);
  });
  it("blocks hallucinated CVEs and wrong counts", () => {
    const result = factCheckDraft("We found 9 findings including CVE-2099-00001.", document);
    expect(result.ok).toBe(false);
    expect(result.unsupportedClaims.join(" ")).toContain("CVE-2099-00001");
    expect(result.unsupportedClaims.join(" ")).toContain("9 findings");
  });
});

describe("metrics (§115–§120)", () => {
  const findings = [
    { id: "1", severity: "CRITICAL", lifecycleStatus: "CONFIRMED", createdAt: "2026-10-01T00:00:00Z", triagedAt: "2026-10-01T10:00:00Z", dueAt: "2026-10-05T00:00:00Z", kevListed: true },
    { id: "2", severity: "HIGH", lifecycleStatus: "RESOLVED", createdAt: "2026-09-01T00:00:00Z", fixClaimedAt: "2026-09-03T00:00:00Z", verifiedClosedAt: "2026-09-05T00:00:00Z" },
    { id: "3", severity: "LOW", lifecycleStatus: "FALSE_POSITIVE", createdAt: "2026-10-02T00:00:00Z" },
    { id: "4", severity: "MEDIUM", lifecycleStatus: "REOPENED", createdAt: "2026-08-01T00:00:00Z", reopenedCount: 2, isRegression: true },
  ];
  it("keeps the three §117 clocks separate and honest", () => {
    const m = computeVulnerabilityMetrics(findings, NOW, new Date("2026-10-01T00:00:00Z"));
    expect(m.openFindings).toBe(2);
    expect(m.newFindings).toBe(2);
    expect(m.verifiedFixes).toBe(1);
    expect(m.meanTimeToTriageHours).toBe(10);
    expect(m.meanTimeToFixClaimHours).toBe(48);
    expect(m.meanTimeToVerifiedClosureHours).toBe(96);
    expect(m.regressions).toBe(1);
    expect(m.slaCompliancePct).toBe(0); // the one SLA-bound open finding is overdue
    expect(m.falsePositiveRate).not.toBeNull();
  });
  it("returns null — never an invented number — when inputs are absent", () => {
    const m = computeVulnerabilityMetrics([], NOW);
    expect(m.meanTimeToTriageHours).toBeNull();
    expect(m.slaCompliancePct).toBeNull();
    expect(m.falsePositiveRate).toBeNull();
  });
  it("trend series uses stored snapshots only, in order", () => {
    const m = computeVulnerabilityMetrics(findings, NOW);
    const series = executiveTrendSeries([
      { capturedAt: "2026-10-08T00:00:00.000Z", metrics: m },
      { capturedAt: "2026-10-01T00:00:00.000Z", metrics: m },
    ]);
    expect(series[0]!.capturedAt).toBe("2026-10-01T00:00:00.000Z");
  });
});

describe("sync decisions (§49–§59)", () => {
  it("maps status/severity both ways without inflating unknowns", () => {
    expect(externalStatusFor("RESOLVED")).toBe("Closed");
    expect(canonicalStatusFor("False Positive")).toBe("FALSE_POSITIVE");
    expect(normalizeSyncSeverity("Moderate")).toBe("MEDIUM");
    expect(normalizeSyncSeverity("weird")).toBe("INFORMATIONAL");
  });
  it("skips our own echo (loop prevention)", () => {
    const hash = syncContentHash({ title: "XSS", severity: "HIGH", status: "CONFIRMED", cve: null });
    const decision = decideSyncRecord(
      { externalId: "e1", title: "XSS", severity: "High", status: "Verified" },
      { externalId: "e1", findingId: "f1", lastSyncedSeverity: "HIGH", lastSyncedStatus: "CONFIRMED", contentHash: hash, localSeverity: "HIGH", localStatus: "CONFIRMED" },
    );
    expect(decision.kind).toBe("SKIP_ECHO");
  });
  it("surfaces a both-sides-changed severity as a conflict, never an overwrite", () => {
    const decision = decideSyncRecord(
      { externalId: "e1", title: "XSS", severity: "Critical", status: "Active" },
      { externalId: "e1", findingId: "f1", lastSyncedSeverity: "HIGH", lastSyncedStatus: "CONFIRMED", contentHash: "other", localSeverity: "MEDIUM", localStatus: "CONFIRMED" },
    );
    expect(decision).toEqual({ kind: "CONFLICT", externalId: "e1", fields: ["severity"] });
  });
  it("treats a one-sided external move as an update and unknown refs as new", () => {
    const decision = decideSyncRecord(
      { externalId: "e1", title: "XSS", severity: "Critical", status: "Active" },
      { externalId: "e1", findingId: "f1", lastSyncedSeverity: "HIGH", lastSyncedStatus: "CONFIRMED", contentHash: "other", localSeverity: "HIGH", localStatus: "CONFIRMED" },
    );
    expect(decision.kind).toBe("UPDATE_LOCAL");
    expect(decideSyncRecord({ externalId: "e9", title: "New", severity: "Low", status: "Active" }, undefined).kind).toBe("IMPORT_NEW");
  });
});
