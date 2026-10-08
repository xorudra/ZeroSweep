import { describe, expect, it } from "vitest";
import {
  NVD_FIXTURE_FEED, NVD_FIXTURE_FEED_SECOND_SOURCE, NVD_FIXTURE_MALICIOUS,
  EPSS_FIXTURE_CSV_DAY1, EPSS_FIXTURE_CSV_DAY2, KEV_FIXTURE_CATALOG_1, ADVISORY_FIXTURE,
} from "./fixtures";
import {
  parseNvdFeed, parseEpssCsv, parseKevCatalog, parseAdvisories, selectPreferredCvss,
  detectConflicts, epssTrend, epssFreshness, epssMateriallyChanged, sanitizeProviderText,
  validateReferenceUrl, snapshotChecksum, intelCacheKey, INTEL_CACHE_TTL_SECONDS, unconfiguredProvider,
} from "./feeds";
import { parsePurl, normalizePurl, validateCpe, resolveComponentIdentity, deriveIdentifierMapping } from "./identity";
import { compareVersionsForEcosystem, evaluateRange, evaluateRanges } from "./versions";
import { correlateComponentToCve, assessReachability } from "./correlation";
import { derivePatchRecords, assessPatchStatus, prioritizeVulnerability, recommendRemediation, computeVulnerabilityBlastRadius, patchLatencyHours, vulnerabilityAges } from "./prioritization";
import { translateVulnQuestion, answerFixQuestion, answerNumericQuestion, NO_VERIFIED_FIX_SENTENCE, type GroundedCveContext } from "./ai";
import type { AffectedRangeData, CvssAssessmentData } from "./types";

const NOW = new Date("2026-10-08T00:00:00Z");
const OBSERVED = "2026-10-08T00:00:00.000Z";

describe("CVE normalization (§131)", () => {
  it("rejects the malformed fixture entry and keeps the well-formed ones", () => {
    const out = parseNvdFeed(NVD_FIXTURE_FEED, OBSERVED, "FIXTURE");
    const ids = out.records.map((r) => r.cve.cveId);
    expect(ids).toContain("CVE-2021-44228");
    expect(ids).toContain("CVE-2023-44487");
    expect(ids).not.toContain("CVE-24-123");
    expect(out.rejected.length).toBe(1);
  });
  it("preserves REJECTED status — never an active vulnerability (§5)", () => {
    const out = parseNvdFeed(NVD_FIXTURE_FEED, OBSERVED, "FIXTURE");
    const rejected = out.records.find((r) => r.cve.cveId === "CVE-2024-3094");
    expect(rejected?.cve.status).toBe("REJECTED");
  });
});

describe("CVSS multi-source (§132/§14/§69)", () => {
  it("preserves both sources and selects the preferred deterministically", () => {
    const a = parseNvdFeed(NVD_FIXTURE_FEED, OBSERVED, "NVD").records.find((r) => r.cve.cveId === "CVE-2021-44228")!;
    const b = parseNvdFeed(NVD_FIXTURE_FEED_SECOND_SOURCE, OBSERVED, "CNA").records.find((r) => r.cve.cveId === "CVE-2021-44228")!;
    const all: CvssAssessmentData[] = [...a.cvss, ...b.cvss];
    expect(all).toHaveLength(2);
    const preferred = selectPreferredCvss(all)!;
    expect(preferred.source).toBe("NVD"); // higher source priority (§7)
    expect(preferred.baseScore).toBe(10.0);
    const preferredAgain = selectPreferredCvss([...all].reverse())!;
    expect(preferredAgain.baseScore).toBe(10.0); // deterministic regardless of order
  });
  it("detects the CVSS + CWE disagreement as conflicts, preserving values", () => {
    const conflicts = detectConflicts({
      cveId: "CVE-2021-44228",
      cvssBySource: [{ source: "NVD", score: 10.0, version: "3.1" }, { source: "CNA", score: 9.3, version: "3.1" }],
      fixedVersionsBySource: [],
      cweBySource: [{ source: "NVD", cweIds: ["CWE-917"] }, { source: "CNA", cweIds: ["CWE-20"] }],
      statusBySource: [{ source: "NVD", status: "MODIFIED" }, { source: "CNA", status: "PUBLISHED" }],
    });
    expect(conflicts.map((c) => c.conflictType)).toEqual(expect.arrayContaining(["CVSS_MISMATCH", "CWE_MISMATCH", "STATUS_MISMATCH"]));
  });
});

describe("EPSS history (§133/§20–§22)", () => {
  it("retains both dated points; trend shows current/previous/change", () => {
    const d1 = parseEpssCsv(EPSS_FIXTURE_CSV_DAY1, "FIXTURE").records.filter((r) => r.cveId === "CVE-2021-44228");
    const d2 = parseEpssCsv(EPSS_FIXTURE_CSV_DAY2, "FIXTURE").records.filter((r) => r.cveId === "CVE-2021-44228");
    const trend = epssTrend([...d1, ...d2])!;
    expect(trend.history).toHaveLength(2);
    expect(trend.current.score).toBe(0.975);
    expect(trend.previous?.score).toBe(0.943);
    expect(trend.change).toBeCloseTo(0.032);
  });
  it("marks stale EPSS and detects material change (44487 crosses 0.5)", () => {
    const pts = [...parseEpssCsv(EPSS_FIXTURE_CSV_DAY1, "FIXTURE").records, ...parseEpssCsv(EPSS_FIXTURE_CSV_DAY2, "FIXTURE").records]
      .filter((r) => r.cveId === "CVE-2023-44487");
    const trend = epssTrend(pts)!;
    expect(epssMateriallyChanged(trend)).toBe(true);
    expect(epssFreshness(trend.current, new Date("2026-11-01T00:00:00Z"))).toBe("STALE");
    expect(epssFreshness(trend.current, NOW)).toBe("CURRENT");
    expect(epssFreshness(undefined, NOW)).toBe("ABSENT");
  });
  it("never renders a missing EPSS as zero — absent stays absent", () => {
    expect(epssTrend([])).toBeUndefined();
  });
});

describe("KEV parser (§23–§25)", () => {
  it("parses catalog entries with due dates + ransomware association", () => {
    const out = parseKevCatalog(KEV_FIXTURE_CATALOG_1, OBSERVED, "FIXTURE");
    expect(out.records).toHaveLength(1);
    expect(out.records[0]).toMatchObject({ cveId: "CVE-2021-44228", dueDate: "2021-12-24", ransomwareAssociation: "Known", status: "ACTIVE" });
  });
});

describe("version comparison (§135)", () => {
  it("is ecosystem-aware, never naive string order", () => {
    expect(compareVersionsForEcosystem("1.10.0", "1.9.0", "npm")).toBe(1);
    expect(compareVersionsForEcosystem("2.0.0-rc.1", "2.0.0", "npm")).toBe(-1);
    expect(compareVersionsForEcosystem("1.0rc1", "1.0", "pypi")).toBe(-1);
    expect(compareVersionsForEcosystem("1.0.post1", "1.0", "pypi")).toBe(1);
    expect(compareVersionsForEcosystem("1.0-rc-1", "1.0", "maven")).toBe(-1);
    expect(compareVersionsForEcosystem("1.0-SNAPSHOT", "1.0", "maven")).toBe(-1);
    expect(compareVersionsForEcosystem("v1.2.3", "1.2.3", "golang")).toBe(0);
    expect(compareVersionsForEcosystem("not-a-version!!", "1.0.0", "pypi")).toBeNull();
  });
});

describe("version ranges + branches (§136/§39)", () => {
  const ranges: AffectedRangeData[] = [
    { cveId: "CVE-2021-44228", vendor: "apache", product: "log4j", ecosystem: "maven", introducedVersion: "2.0.0", fixedVersion: "2.12.2", confidence: "HIGH", source: "FIXTURE" },
    { cveId: "CVE-2021-44228", vendor: "apache", product: "log4j", ecosystem: "maven", introducedVersion: "2.13.0", fixedVersion: "2.15.0", confidence: "HIGH", source: "FIXTURE" },
  ];
  it("evaluates branch-specific status correctly", () => {
    expect(evaluateRanges("2.12.1", ranges).verdict).toBe("AFFECTED"); // branch A
    expect(evaluateRanges("2.14.1", ranges).verdict).toBe("AFFECTED"); // branch B
    expect(evaluateRanges("2.12.2", ranges).verdict).toBe("NOT_AFFECTED"); // fixed in branch A, before branch B starts
    expect(evaluateRanges("2.15.0", ranges).verdict).toBe("NOT_AFFECTED");
    expect(evaluateRanges("1.9.9", ranges).verdict).toBe("NOT_AFFECTED");
  });
  it("lastAffected is inclusive; expression-only ranges are UNCERTAIN", () => {
    const r: AffectedRangeData = { cveId: "CVE-X", vendor: "v", product: "p", lastAffectedVersion: "3.0.0", confidence: "MEDIUM", source: "FIXTURE" };
    expect(evaluateRange("3.0.0", r).verdict).toBe("AFFECTED");
    expect(evaluateRange("3.0.1", r).verdict).toBe("NOT_AFFECTED");
    const exprOnly: AffectedRangeData = { cveId: "CVE-X", vendor: "v", product: "p", rangeExpression: ">=2.0, <2.5", confidence: "LOW", source: "FIXTURE" };
    expect(evaluateRange("2.2.0", exprOnly).verdict).toBe("UNCERTAIN");
  });
});

describe("PURL (§137) + CPE (§138)", () => {
  it("normalizes equivalent PURLs to the same identity", () => {
    const a = normalizePurl("pkg:npm/Lodash@4.17.21");
    const b = normalizePurl("pkg:npm/lodash@4.17.21");
    expect(a).toBe(b);
    expect(normalizePurl("pkg:pypi/Flask_Login@0.5.0")).toBe(normalizePurl("pkg:pypi/flask-login@0.5.0"));
    expect(parsePurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")?.namespace).toBe("org.apache.logging.log4j");
    // percent-encoded and literal spellings of the same scoped package
    // normalize to ONE identity (§137)
    expect(normalizePurl("pkg:npm/%40angular/core@12.0.0")).toBe(normalizePurl("pkg:npm/@angular/core@12.0.0"));
    expect(parsePurl("pkg:npm/%40angular/core@12.0.0")?.namespace).toBe("@angular");
    expect(parsePurl("not-a-purl")).toBeUndefined();
    expect(parsePurl("pkg:")).toBeUndefined();
  });
  it("validates CPEs and rejects malformed/unsafe input", () => {
    expect(validateCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*").ok).toBe(true);
    expect(validateCpe("cpe:2.3:a:*:log4j:*:*:*:*:*:*:*:*").ok).toBe(false);
    expect(validateCpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*\u0007").ok).toBe(false);
    expect(validateCpe("javascript:alert(1)").ok).toBe(false);
  });
  it("resolves component identity with the right confidence (§49/§50)", () => {
    expect(resolveComponentIdentity({ name: "log4j-core", purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }).confidence).toBe("EXACT");
    expect(resolveComponentIdentity({ name: "log4j", cpe: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" }).confidence).toBe("HIGH");
    expect(resolveComponentIdentity({ name: "log4j" }).confidence).toBe("LOW");
    expect(deriveIdentifierMapping({ purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" })?.product).toBe("log4j-core");
  });
});

describe("SBOM correlation (§139–§141)", () => {
  const feed = parseNvdFeed(NVD_FIXTURE_FEED, OBSERVED, "FIXTURE");
  const log4j = feed.records.find((r) => r.cve.cveId === "CVE-2021-44228")!;
  const ranges: AffectedRangeData[] = log4j.ranges;
  const products = log4j.affectedProducts;

  it("exact CPE match + in-range version ⇒ AFFECTED (§139)", () => {
    const m = correlateComponentToCve({
      component: { id: "c1", name: "log4j", version: "2.14.1", ecosystem: "maven", purl: "pkg:maven/org.apache.logging.log4j/log4j@2.14.1", cpe: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" },
      cveId: "CVE-2021-44228", ranges, affectedProducts: products,
    });
    expect(m.affectedStatus).toBe("AFFECTED");
    expect(m.confidence).toBe("HIGH");
  });
  it("exact match + fixed-branch version ⇒ NOT_AFFECTED", () => {
    const m = correlateComponentToCve({
      component: { id: "c2", name: "log4j", version: "2.12.2", ecosystem: "maven", purl: "pkg:maven/org.apache.logging.log4j/log4j@2.12.2", cpe: "cpe:2.3:a:apache:log4j:2.12.2:*:*:*:*:*:*:*" },
      cveId: "CVE-2021-44228", ranges, affectedProducts: products,
    });
    expect(m.affectedStatus).toBe("NOT_AFFECTED");
  });
  it("name similarity alone ⇒ POTENTIALLY_AFFECTED, never confirmed (§140)", () => {
    const m = correlateComponentToCve({
      component: { id: "c3", name: "log4j", ecosystem: "generic", purl: "pkg:generic/log4j" },
      cveId: "CVE-2021-44228", ranges, affectedProducts: products,
    });
    expect(m.affectedStatus).toBe("POTENTIALLY_AFFECTED");
    expect(m.matchType).toBe("HEURISTIC");
  });
  it("scanner disagreement preserves both observations (§141)", () => {
    const m = correlateComponentToCve({
      component: { id: "c4", name: "log4j", version: "2.14.1", ecosystem: "maven", purl: "pkg:maven/org.apache.logging.log4j/log4j@2.14.1" },
      cveId: "CVE-2021-44228", ranges, affectedProducts: products,
      scannerObservations: [{ scanner: "trivy", affected: true }, { scanner: "grype", affected: false }],
    });
    expect(m.affectedStatus).toBe("POTENTIALLY_AFFECTED");
    expect(m.confidence).toBe("AMBIGUOUS");
    expect(m.evidence.join(" ")).toContain("trivy");
    expect(m.evidence.join(" ")).toContain("grype");
  });
  it("one scanner confirms with no dissent ⇒ AFFECTED / SCANNER_CONFIRMED", () => {
    const m = correlateComponentToCve({
      component: { id: "c5", name: "log4j", version: "2.14.1", ecosystem: "maven", purl: "pkg:maven/x/log4j@2.14.1" },
      cveId: "CVE-2021-44228", ranges: [], affectedProducts: [],
      scannerObservations: [{ scanner: "trivy", affected: true }],
    });
    expect(m.affectedStatus).toBe("AFFECTED");
    expect(m.matchType).toBe("SCANNER_CONFIRMED");
  });
});

describe("patch intelligence (§142/§143/§85/§86)", () => {
  it("creates PatchRecords from reliable advisories", () => {
    const advisories = parseAdvisories(ADVISORY_FIXTURE, "GHSA", "FIXTURE").records;
    const patches = derivePatchRecords(advisories);
    const fix = patches.find((p) => p.cveId === "CVE-2021-44228" && p.fixedVersion);
    expect(fix?.fixedVersion).toBe("2.15.0");
    expect(fix?.status).toBe("FIXED_VERSION_AVAILABLE");
  });
  it("no-fix CVE: mitigation-only / NO_KNOWN_FIX, and the AI invents nothing", () => {
    const advisories = parseAdvisories(ADVISORY_FIXTURE, "GHSA", "FIXTURE").records;
    const patches = derivePatchRecords(advisories).filter((p) => p.cveId === "CVE-2023-44487");
    const assessment = assessPatchStatus({ patchRecords: patches, advisoriesExamined: 1, intelRecordsExamined: 1 });
    expect(["MITIGATION_ONLY", "NO_KNOWN_FIX"]).toContain(assessment.status);
    expect(assessment.fixedVersion).toBeUndefined();
    const ctx: GroundedCveContext = { cveId: "CVE-2023-44487", hasRecord: true, kevListed: true, patchStatus: assessment.status, mitigation: assessment.mitigation, affectedAssetsConfirmed: 0, affectedAssetsPotential: 0 };
    const answer = answerFixQuestion(ctx);
    expect(answer.answer).toContain(NO_VERIFIED_FIX_SENTENCE);
    expect(answer.executed).toBe(false);
  });
  it("conflicting fixed versions are shown, never flattened (§86)", () => {
    const assessment = assessPatchStatus({
      patchRecords: [
        { cveId: "CVE-1", productKey: "maven:log4j-core", fixedVersion: "2.15.0", status: "FIXED_VERSION_AVAILABLE", confidence: "HIGH", source: "GHSA" },
        { cveId: "CVE-1", productKey: "maven:log4j-core", fixedVersion: "2.16.0", status: "FIXED_VERSION_AVAILABLE", confidence: "HIGH", source: "VENDOR" },
      ],
      advisoriesExamined: 2, intelRecordsExamined: 0,
    });
    expect(assessment.status).toBe("UNKNOWN");
    expect(assessment.fixedVersion).toBeUndefined();
    expect(assessment.conflictingFixedVersions).toBeDefined();
  });
  it("UNKNOWN (not NO_KNOWN_FIX) when nothing was examined", () => {
    const assessment = assessPatchStatus({ patchRecords: [], advisoriesExamined: 0, intelRecordsExamined: 0 });
    expect(assessment.status).toBe("UNKNOWN");
  });
});

describe("blast radius + dependency paths (§144/§145/§80)", () => {
  it("counts repo/image/workload/asset reach with confirmed ≠ potential", () => {
    const br = computeVulnerabilityBlastRadius("CVE-2021-44228", [
      { componentId: "c1", componentName: "log4j", appearanceKind: "REPOSITORY", appearanceId: "repo-1", appearanceLabel: "payments-api", dependencyScope: "DIRECT", dependencyPath: ["payments-api", "log4j-core"], deployedTo: [{ kind: "WORKLOAD", id: "w1", label: "payments" }, { kind: "ASSET", id: "a1", label: "prod host", internetExposed: true }], affectedStatus: "AFFECTED" },
      { componentId: "c1", componentName: "log4j", appearanceKind: "IMAGE", appearanceId: "img-1", appearanceLabel: "payments:1.2", dependencyScope: "TRANSITIVE", dependencyPath: ["payments", "spring-boot", "log4j-core"], deployedTo: [{ kind: "WORKLOAD", id: "w1", label: "payments" }], affectedStatus: "AFFECTED" },
      { componentId: "c2", componentName: "log4j", appearanceKind: "REPOSITORY", appearanceId: "repo-2", appearanceLabel: "legacy", dependencyScope: "TRANSITIVE", deployedTo: [], affectedStatus: "POTENTIALLY_AFFECTED" },
    ]);
    expect(br.confirmed.components).toBe(1);
    expect(br.confirmed.repositories).toBe(1);
    expect(br.confirmed.images).toBe(1);
    expect(br.confirmed.workloads).toBe(1);
    expect(br.confirmed.assets).toBe(1);
    expect(br.potential.repositories).toBe(1);
    expect(br.transitiveCount).toBe(2); // §145: transitive appearances tracked with paths
    expect(br.appearances[1]?.dependencyPath).toEqual(["payments", "spring-boot", "log4j-core"]);
  });
});

describe("reachability (§146/§147/§77)", () => {
  it("call-path evidence ⇒ REACHABLE; incomplete analysis ⇒ never NOT_REACHABLE", () => {
    expect(assessReachability({ callPathEvidence: true }).status).toBe("REACHABLE");
    expect(assessReachability({ analysisIncomplete: true }).status).toBe("UNKNOWN");
    expect(assessReachability({}).status).toBe("UNKNOWN");
    expect(assessReachability({ directDependency: true }).status).toBe("POTENTIALLY_REACHABLE");
    expect(assessReachability({ positiveUnreachableEvidence: true }).status).toBe("NOT_REACHABLE");
  });
});

describe("prioritization (§148/§149/§92)", () => {
  it("same CVSS: internet-facing critical KEV asset scores materially higher", () => {
    const internal = prioritizeVulnerability({ cveId: "CVE-2021-44228", cvssScore: 10.0, kevListed: false, internetExposed: false, assetCriticality: "LOW", verified: false, patchStatus: "FIXED_VERSION_AVAILABLE", confirmedAffectedAssets: 1, potentialAffectedAssets: 0 });
    const exposed = prioritizeVulnerability({ cveId: "CVE-2021-44228", cvssScore: 10.0, epssScore: 0.975, kevListed: true, internetExposed: true, assetCriticality: "CRITICAL", verified: true, exploitMaturity: "ACTIVE_EXPLOITATION_REPORTED", patchStatus: "FIXED_VERSION_AVAILABLE", confirmedAffectedAssets: 5, potentialAffectedAssets: 2 });
    expect(exposed.priorityScore - internal.priorityScore).toBeGreaterThanOrEqual(30);
    expect(exposed.why.join(" ")).toContain("KEV");
  });
  it("recommendations differ for fix-available vs no-fix (§149)", () => {
    const withFix = recommendRemediation({ patch: assessPatchStatus({ patchRecords: [{ cveId: "C", productKey: "a:b", fixedVersion: "2.0", status: "FIXED_VERSION_AVAILABLE", confidence: "HIGH", source: "GHSA" }], advisoriesExamined: 1, intelRecordsExamined: 0 }), internetExposed: true, kevListed: true });
    expect(withFix.action).toBe("UPGRADE_TO_FIXED_VERSION");
    expect(withFix.fixedVersion).toBe("2.0");
    const noFix = recommendRemediation({ patch: assessPatchStatus({ patchRecords: [], advisoriesExamined: 1, intelRecordsExamined: 1 }), internetExposed: true, kevListed: true });
    expect(noFix.action).toBe("ISOLATE_OR_RESTRICT_EXPOSURE");
    expect(noFix.fixedVersion).toBeUndefined();
  });
});

describe("provider hardening (§152–§154/§127–§129)", () => {
  it("unconfigured provider refuses live fetch honestly", async () => {
    const p = unconfiguredProvider("NVD");
    await expect(p.fetchCve("CVE-2021-44228")).rejects.toThrow(/not configured/);
    expect(p.healthCheck().status).toBe("NOT_CONFIGURED");
  });
  it("sanitizes hostile provider text and drops non-http(s) references", () => {
    const out = parseNvdFeed(NVD_FIXTURE_MALICIOUS, OBSERVED, "FIXTURE");
    const rec = out.records[0]!;
    expect(rec.cve.description).not.toContain("<script>");
    expect(rec.cve.description).not.toContain("\u0007");
    const urls = rec.cve.references.map((r) => r.url);
    expect(urls.some((u) => u.startsWith("javascript:"))).toBe(false);
    // The metadata-endpoint URL survives ONLY as an inert reference string —
    // this module exposes no fetch surface at all (§129).
    expect(validateReferenceUrl("javascript:alert(1)")).toBeUndefined();
    expect(validateReferenceUrl("https://example.com/x")).toBe("https://example.com/x");
    expect(sanitizeProviderText("<b>hi</b>")).not.toContain("<b>");
  });
  it("checksums + cache keys are provider-scoped (§125/§126)", () => {
    expect(snapshotChecksum("abc")).toBe(snapshotChecksum("abc"));
    expect(snapshotChecksum("abc")).not.toBe(snapshotChecksum("abd"));
    expect(intelCacheKey("NVD", "CVE-2021-44228")).toBe("intel:nvd:v1:CVE-2021-44228");
    expect(INTEL_CACHE_TTL_SECONDS.NVD).toBeGreaterThan(0);
  });
});

describe("AI grounding + NL translation (§111/§150/§151)", () => {
  it("translates the spec's example questions deterministically", () => {
    expect(translateVulnQuestion("Show internet-facing KEV vulnerabilities with patches.")).toMatchObject({ kev: true, internetExposed: true, patchStatus: "FIXED_VERSION_AVAILABLE" });
    expect(translateVulnQuestion("Which high EPSS vulnerabilities affect production?")).toMatchObject({ minEpss: 0.5, productionOnly: true });
    expect(translateVulnQuestion("Which CVEs affect more than 20 assets?")).toMatchObject({ minAffectedAssets: 20 });
    expect(translateVulnQuestion("tell me a joke")).toBeNull();
  });
  it("numeric answers quote stored values only (§151)", () => {
    const ctx: GroundedCveContext = { cveId: "CVE-2021-44228", hasRecord: true, kevListed: true, patchStatus: "FIXED_VERSION_AVAILABLE", fixedVersion: "2.15.0", epss: { score: 0.975, percentile: 0.9995, date: "2026-10-07", freshness: "CURRENT" }, cvss: { score: 10.0, version: "3.1", source: "NVD" }, affectedAssetsConfirmed: 3, affectedAssetsPotential: 1 };
    expect(answerNumericQuestion(ctx, "epss").answer).toContain("0.975");
    expect(answerNumericQuestion(ctx, "cvss").answer).toContain("10");
    const bare: GroundedCveContext = { cveId: "CVE-0000-0000", hasRecord: false, kevListed: false, patchStatus: "UNKNOWN", affectedAssetsConfirmed: 0, affectedAssetsPotential: 0 };
    expect(answerNumericQuestion(bare, "epss").answer).toContain("never rendered as 0");
  });
  it("patch latency + ages use the defined formulas (§105/§106)", () => {
    expect(patchLatencyHours("2026-10-01T00:00:00Z", "2026-10-03T00:00:00Z")).toBe(48);
    expect(patchLatencyHours(undefined, "2026-10-03T00:00:00Z")).toBeNull();
    const ages = vulnerabilityAges({ cvePublishedAt: "2021-12-10T00:00:00Z", findingFirstSeenAt: "2026-10-01T00:00:00Z" }, NOW);
    expect(ages.findingAgeDays).toBe(7);
    expect(ages.exposureAgeDays).toBeNull();
    expect(ages.cveAgeDays).toBeGreaterThan(1000);
  });
});
