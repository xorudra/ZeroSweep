import { describe, expect, it } from "vitest";
import { capEvidence, csvSafeCell, escapeForDisplay, prepareEvidence, redactEvidenceText, sanitizeReferenceUrl } from "./redact";

/** Hostile scanner output handling (Prompt 7 §30/§31/§54/§55/§56/§63). */
describe("evidence redaction + caps (§30/§31)", () => {
  it("redacts Authorization, cookies, bearer tokens and secret fields", () => {
    const raw = [
      "GET / HTTP/1.1", "Authorization: Bearer abc.def.ghi", "Cookie: session=xyz; theme=dark",
      "Set-Cookie: sessionid=topsecret; Path=/", '{"password":"hunter2","user":"a"}',
      "https://example.com/cb?token=zzz&next=/home", "password=hunter2&x=1",
    ].join("\n");
    const out = redactEvidenceText(raw);
    for (const secret of ["abc.def.ghi", "xyz", "topsecret", "hunter2", "zzz"]) expect(out).not.toContain(secret);
    expect(out).toContain("[REDACTED]");
    // A Cookie header is redacted as a whole (theme=dark lived inside it);
    // genuinely non-secret content survives untouched.
    expect(out).not.toContain("theme=dark");
    expect(redactEvidenceText("X-Theme: dark\nServer: nginx")).toContain("X-Theme: dark");
  });

  it("caps oversized evidence with truncation marker + checksum of the original", () => {
    const big = "A".repeat(10_000);
    const capped = capEvidence(big, 1_000);
    expect(capped.truncated).toBe(true);
    expect(capped.originalBytes).toBe(10_000);
    expect(capped.text).toMatch(/truncated/);
    expect(capped.checksum).toHaveLength(64);
    const small = prepareEvidence("ok", 1_000);
    expect(small.truncated).toBe(false);
  });
});

describe("reference URL validation (§54)", () => {
  it("accepts plain http/https and strips embedded credentials", () => {
    expect(sanitizeReferenceUrl("https://nvd.nist.gov/vuln/detail/CVE-2021-0001")).toContain("nvd.nist.gov");
    expect(sanitizeReferenceUrl("https://user:pass@example.com/x")).toBeUndefined();
  });
  it("rejects javascript:, data:, protocol-relative and malformed URLs", () => {
    expect(sanitizeReferenceUrl("javascript:alert(1)")).toBeUndefined();
    expect(sanitizeReferenceUrl("data:text/html,<script>")).toBeUndefined();
    expect(sanitizeReferenceUrl("//evil.example/x")).toBeUndefined();
    expect(sanitizeReferenceUrl("not a url")).toBeUndefined();
  });
});

describe("display + export safety (§55/§56)", () => {
  it("escapes markup so stored evidence renders as inert text", () => {
    expect(escapeForDisplay(`<script>alert("x")</script>`)).toBe("&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;");
  });
  it("neutralizes spreadsheet formula prefixes", () => {
    expect(csvSafeCell("=2+5")).toBe("'=2+5");
    expect(csvSafeCell("+SUM(A1)")).toBe("'+SUM(A1)");
    expect(csvSafeCell("normal")).toBe("normal");
  });
});
