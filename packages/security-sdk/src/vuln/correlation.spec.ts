import { describe, expect, it } from "vitest";
import { assessConfidence, canonicalFindingFingerprint, computeRisk } from "./analysis";
import { correlateFindings } from "./correlation";
import { NIKTO_JSON, NUCLEI_JSONL, SSLYZE_JSON, TESTSSL_JSON } from "./fixtures";
import { NiktoParser, NucleiParser, SslyzeParser, TestsslParser } from "./parsers-vuln";
import type { NormalizedVulnFinding } from "./types";

function allFixtureFindings(): NormalizedVulnFinding[] {
  return [
    ...new NucleiParser().parse(NUCLEI_JSONL).findings,
    ...new NiktoParser().parse(NIKTO_JSON).findings,
    ...new TestsslParser().parse(TESTSSL_JSON).findings,
    ...new SslyzeParser().parse(SSLYZE_JSON).findings,
  ];
}

/**
 * Deduplication + correlation (Prompt 7 §20/§21/§60): same underlying issue
 * from several tools = ONE canonical finding, all evidence preserved.
 */
describe("correlateFindings (§60)", () => {
  const { findings, stats } = correlateFindings(allFixtureFindings());

  it("merges the TLS 1.0 issue from nuclei + testssl + sslyze into ONE canonical finding with 3 sources", () => {
    const tls = findings.filter((c) => c.finding.vulnClass === "TLS_WEAK_PROTOCOL");
    expect(tls).toHaveLength(1);
    const tools = tls[0]!.sources.map((s) => s.tool).sort();
    expect(tools).toEqual(["nuclei", "sslyze", "testssl"]);
    expect(tls[0]!.dedupState).toBe("DUPLICATE");
    expect(stats.duplicatesMerged).toBeGreaterThanOrEqual(2);
  });

  it("merges missing-headers from nuclei + nikto (+ testssl HSTS stays its own endpoint-less TLS-service report)", () => {
    const headers = findings.filter((c) => c.finding.vulnClass === "MISSING_SECURITY_HEADERS" && c.finding.endpoint === "https://example.com/");
    expect(headers).toHaveLength(1);
    expect(headers[0]!.sources.map((s) => s.tool).sort()).toEqual(["nikto", "nuclei"]);
  });

  it("keeps similar-but-different findings separate (cookie flag vs directory listing)", () => {
    expect(findings.some((c) => c.finding.vulnClass === "COOKIE_NO_HTTPONLY")).toBe(true);
    expect(findings.some((c) => c.finding.vulnClass === "DIRECTORY_LISTING")).toBe(true);
    const cookie = findings.find((c) => c.finding.vulnClass === "COOKIE_NO_HTTPONLY")!;
    expect(cookie.sources).toHaveLength(1);
  });

  it("tracks tool contribution: totals, uniques, corroborated (§46)", () => {
    expect(stats.byTool.nuclei!.total).toBeGreaterThan(0);
    expect(stats.byTool.testssl!.corroborated).toBeGreaterThan(0);
    expect(stats.corroborated).toBeGreaterThanOrEqual(2);
  });

  it("enforces maxFindings as a RECORDED limit event, not a silent drop (§51)", () => {
    const limited = correlateFindings(allFixtureFindings(), { maxFindings: 2 });
    expect(limited.findings).toHaveLength(2);
    expect(limited.stats.limitEvent).toEqual(expect.objectContaining({ type: "MAX_FINDINGS_REACHED", kept: 2 }));
    expect(limited.stats.limitEvent!.dropped).toBeGreaterThan(0);
    // Highest-risk findings are the ones kept.
    const scores = limited.findings.map((f) => f.riskScore);
    expect(scores[0]!).toBeGreaterThanOrEqual(scores[1]!);
  });
});

describe("confidence model (§22)", () => {
  it("corroboration from independent tools raises confidence", () => {
    const a = assessConfidence({ sources: [
      { tool: "testssl", confidence: 0.85, signatureFamily: "testssl-check:TLS1" },
      { tool: "sslyze", confidence: 0.85, signatureFamily: "sslyze-protocol:tls" },
    ] });
    expect(a.score).toBeCloseTo(0.97);
    expect(a.verificationStatus).toBe("LIKELY"); // still not CONFIRMED
  });

  it("two reports sharing one signature family add NO bonus (same upstream signature)", () => {
    const a = assessConfidence({ sources: [
      { tool: "tool-a", confidence: 0.8, signatureFamily: "shared-sig" },
      { tool: "tool-b", confidence: 0.8, signatureFamily: "shared-sig" },
    ] });
    expect(a.score).toBeCloseTo(0.8);
    expect(a.rationale.some((r) => /no corroboration bonus/.test(r))).toBe(true);
  });

  it("CONFIRMED requires deterministic verification, never mere agreement", () => {
    const a = assessConfidence({ sources: [{ tool: "x", confidence: 0.99, signatureFamily: "s" }], deterministicVerification: true });
    expect(a.verificationStatus).toBe("CONFIRMED");
  });
});

describe("fingerprint + risk (§19/§34/§35)", () => {
  it("canonical fingerprint is tool-independent and deterministic", () => {
    const a = canonicalFindingFingerprint({ host: "Example.com", port: 443, vulnClass: "TLS_WEAK_PROTOCOL" });
    const b = canonicalFindingFingerprint({ host: "example.com", port: 443, vulnClass: "TLS_WEAK_PROTOCOL" });
    expect(a).toBe(b);
    const c = canonicalFindingFingerprint({ host: "example.com", port: 8443, vulnClass: "TLS_WEAK_PROTOCOL" });
    expect(c).not.toBe(a);
  });

  it("risk score is explained, CVSS-driven when provided, and 0 when REJECTED", () => {
    const withCvss = computeRisk({ severity: "LOW", cvssScore: 9.0, confidence: 1 });
    expect(withCvss.explanation[0]).toMatch(/CVSS/);
    expect(withCvss.score).toBe(90);
    const rejected = computeRisk({ severity: "CRITICAL", confidence: 1, verificationStatus: "REJECTED" });
    expect(rejected.score).toBe(0);
    const crit = computeRisk({ severity: "MEDIUM", confidence: 0.5, assetCriticality: "CRITICAL", internetExposed: true });
    expect(crit.score).toBeGreaterThan(computeRisk({ severity: "MEDIUM", confidence: 0.5 }).score);
  });
});
