import { describe, expect, it } from "vitest";
import {
  canonicalizeHostname, canonicalizeUrl, extractParameterNames, redactSensitiveText, redactUrl,
} from "./normalize";

describe("hostname canonicalization (§19)", () => {
  it("lowercases and strips the trailing dot", () => {
    expect(canonicalizeHostname("API.Example.COM.")).toBe("api.example.com");
    expect(canonicalizeHostname("  www.example.com ")).toBe("www.example.com");
  });
  it("converts IDN to punycode so representations cannot diverge", () => {
    expect(canonicalizeHostname("münchen.example.com")).toBe("xn--mnchen-3ya.example.com");
  });
  it("rejects scope-bypass shapes: wildcards, underscores, credentials, paths", () => {
    expect(canonicalizeHostname("*.example.com")).toBeNull();
    expect(canonicalizeHostname("bad_host.example.com")).toBeNull();
    expect(canonicalizeHostname("user@example.com")).toBeNull();
    expect(canonicalizeHostname("example.com/path")).toBeNull();
    expect(canonicalizeHostname("-bad.example.com")).toBeNull();
    expect(canonicalizeHostname("nodot")).toBeNull();
    expect(canonicalizeHostname("")).toBeNull();
  });
  it("accepts strict IPv4 literals only", () => {
    expect(canonicalizeHostname("93.184.216.34")).toBe("93.184.216.34");
    expect(canonicalizeHostname("999.1.1.1")).toBeNull();
  });
});

describe("URL canonicalization (§20)", () => {
  it("normalizes scheme/host case, default ports, fragments and duplicate slashes", () => {
    expect(canonicalizeUrl("HTTPS://Example.COM:443//a//b#frag")).toBe("https://example.com/a/b");
    expect(canonicalizeUrl("http://example.com:80/x")).toBe("http://example.com/x");
    expect(canonicalizeUrl("https://example.com:8443/x")).toBe("https://example.com:8443/x");
  });
  it("keeps path case and query — different endpoints are not merged", () => {
    expect(canonicalizeUrl("https://example.com/Case/Path?b=2&a=1")).toBe("https://example.com/Case/Path?b=2&a=1");
  });
  it("rejects non-http(s) and embedded credentials", () => {
    expect(canonicalizeUrl("ftp://example.com/x")).toBeNull();
    expect(canonicalizeUrl("https://user:pass@example.com/")).toBeNull();
    expect(canonicalizeUrl("not a url")).toBeNull();
  });
});

describe("parameter names + redaction (§21–§22)", () => {
  it("extracts sorted unique parameter names only", () => {
    expect(extractParameterNames("https://example.com/p?b=2&id=1&b=3")).toEqual(["b", "id"]);
  });
  it("redacts sensitive parameter values but keeps names", () => {
    const redacted = redactUrl("https://example.com/p?id=42&token=supersecretvalue&lang=en");
    expect(redacted).toContain("id=42");
    expect(redacted).toContain("token=REDACTED");
    expect(redacted).not.toContain("supersecretvalue");
  });
  it("redacts emails, bearer tokens and API-key shapes in free text", () => {
    const out = redactSensitiveText("contact admin@example.com with Bearer abcdef1234567890 and ghp_1234567890abcdef");
    expect(out).not.toContain("admin@example.com");
    expect(out).not.toContain("abcdef1234567890");
    expect(out).not.toContain("ghp_1234567890abcdef");
  });
});
