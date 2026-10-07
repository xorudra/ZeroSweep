import { describe, expect, it } from "vitest";
import { NIKTO_JSON, NUCLEI_JSONL, SSLYZE_JSON, TESTSSL_EXPIRED_JSON, TESTSSL_JSON } from "./fixtures";
import { NiktoParser, NucleiParser, SslyzeParser, TestsslParser } from "./parsers-vuln";

/**
 * Parser tests (Prompt 7 §15/§58/§59): recorded outputs only — no tool
 * executed, no network. Findings exist only because the fixtures contain
 * them; CVE/CVSS stay absent when the output never provided them.
 */
describe("NucleiParser (§58)", () => {
  const parsed = new NucleiParser().parse(NUCLEI_JSONL);

  it("parses valid JSONL records and warns on the malformed line", () => {
    expect(parsed.records).toBe(5);
    expect(parsed.warnings.some((w) => /invalid JSON|skipped/i.test(w))).toBe(true);
  });

  it("normalizes template findings with taxonomy CWE/OWASP and no invented CVE/CVSS", () => {
    const headers = parsed.findings.find((f) => f.templateId === "http-missing-security-headers")!;
    expect(headers.vulnClass).toBe("MISSING_SECURITY_HEADERS");
    expect(headers.cwe).toBe("CWE-693"); // curated taxonomy
    expect(headers.owaspCategory).toMatch(/A05:2021/);
    expect(headers.cve).toBeUndefined(); // never invented
    expect(headers.cvssScore).toBeUndefined();
    expect(headers.endpoint).toBe("https://example.com/");
    expect(headers.sourceFingerprint).toBeTruthy();
  });

  it("redacts credentials from stored evidence (§30)", () => {
    const headers = parsed.findings.find((f) => f.templateId === "http-missing-security-headers")!;
    expect(headers.evidenceDetail!.request).not.toContain("fixture-secret-token");
    expect(headers.evidenceDetail!.request).toContain("[REDACTED]");
    expect(headers.evidenceDetail!.response).not.toContain("fixture-session-value");
  });

  it("maps the TLS template to the TLS class on port 443 with no endpoint", () => {
    const tls = parsed.findings.find((f) => f.templateId === "tls-version")!;
    expect(tls.vulnClass).toBe("TLS_WEAK_PROTOCOL");
    expect(tls.port).toBe(443);
    expect(tls.endpoint).toBeUndefined();
  });
});

describe("NiktoParser (§10)", () => {
  const parsed = new NiktoParser().parse(NIKTO_JSON);

  it("classifies messages by parser rules instead of promoting everything", () => {
    const classes = parsed.findings.map((f) => f.vulnClass);
    expect(classes).toContain("MISSING_SECURITY_HEADERS");
    expect(classes).toContain("DIRECTORY_LISTING");
    expect(classes).toContain("OUTDATED_SOFTWARE");
    expect(classes).toContain("SERVER_MISCONFIGURATION");
  });

  it("keeps the banner as technology observation, not a finding", () => {
    expect(parsed.observations.some((o) => o.kind === "TECHNOLOGY" && /nginx/.test(o.summary))).toBe(true);
    expect(parsed.findings.some((f) => /Interesting banner/.test(f.title))).toBe(false);
    expect(parsed.observations.some((o) => /Interesting banner/.test(o.summary))).toBe(true);
  });

  it("builds absolute endpoints from host + path", () => {
    const dir = parsed.findings.find((f) => f.vulnClass === "DIRECTORY_LISTING")!;
    expect(dir.endpoint).toBe("https://example.com/config/");
  });

  it("survives malformed output as warnings, not exceptions", () => {
    const bad = new NiktoParser().parse("not json at all");
    expect(bad.findings).toHaveLength(0);
  });
});

describe("TestsslParser (§59)", () => {
  const parsed = new TestsslParser().parse(TESTSSL_JSON);

  it("turns deprecated protocol + weak cipher + missing HSTS into findings; OK/INFO stay observations", () => {
    const classes = parsed.findings.map((f) => f.vulnClass);
    expect(classes).toContain("TLS_WEAK_PROTOCOL");
    expect(classes).toContain("TLS_WEAK_CIPHER");
    expect(classes).toContain("MISSING_SECURITY_HEADERS");
    expect(parsed.observations.length).toBeGreaterThanOrEqual(3); // SSLv3 OK, cert INFO, cert OK
    expect(parsed.findings.every((f) => f.port === 443 && f.host === "example.com")).toBe(true);
  });

  it("carries the source-provided CWE and no invented CVE", () => {
    const cipher = parsed.findings.find((f) => f.vulnClass === "TLS_WEAK_CIPHER")!;
    expect(cipher.cwe).toBe("CWE-327");
    expect(cipher.cve).toBeUndefined();
  });

  it("flags an expired certificate from the dedicated fixture", () => {
    const expired = new TestsslParser().parse(TESTSSL_EXPIRED_JSON);
    expect(expired.findings).toHaveLength(1);
    expect(expired.findings[0]!.vulnClass).toBe("TLS_CERTIFICATE_EXPIRED");
    expect(expired.findings[0]!.severity).toBe("HIGH");
  });

  it("handles non-JSON output safely", () => {
    const bad = new TestsslParser().parse("<html>error</html>");
    expect(bad.findings).toHaveLength(0);
    expect(bad.warnings.length).toBeGreaterThan(0);
  });
});

describe("SslyzeParser (§59)", () => {
  const parsed = new SslyzeParser().parse(SSLYZE_JSON);

  it("reports only the weak protocol actually accepted (TLS 1.0)", () => {
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]!.vulnClass).toBe("TLS_WEAK_PROTOCOL");
    expect(parsed.findings[0]!.severity).toBe("MEDIUM");
  });

  it("a valid, trusted certificate produces no certificate findings", () => {
    expect(parsed.findings.some((f) => /CERTIFICATE/.test(f.vulnClass))).toBe(false);
    expect(parsed.services).toEqual([{ host: "example.com", port: 443, protocol: "tcp", name: "https", scheme: "https" }]);
  });
});
