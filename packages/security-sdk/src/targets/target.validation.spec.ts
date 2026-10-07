import { describe, expect, it } from "vitest";
import { assertResolvedAddressesSafe, assertValidTarget, validateTargetValue } from "./target.validation";

/** Prompt 3 §46 — malicious values are treated as data and rejected, never
 *  transformed into executable shell syntax. */
describe("validateTargetValue (security)", () => {
  it("accepts plain domains, URLs, IPs and CIDRs", () => {
    expect(validateTargetValue("example.com").valid).toBe(true);
    expect(validateTargetValue("https://app.example.com/path").valid).toBe(true);
    expect(validateTargetValue("8.8.8.8").valid).toBe(true);
    expect(validateTargetValue("8.8.8.0/24").valid).toBe(true);
  });
  it("rejects shell separators and metacharacters", () => {
    for (const bad of ["example.com; rm -rf /", "a|nc -e sh", "$(id).example.com", "`id`.example.com", "example.com && curl evil", "example.com\nid", "exa mple.com"]) {
      const r = validateTargetValue(bad);
      expect(r.valid, bad).toBe(false);
      expect(r.reasonCode).toBe("SHELL_METACHARACTERS");
    }
  });
  it("rejects invalid protocols and embedded credentials", () => {
    expect(validateTargetValue("ftp://example.com").reasonCode).toBe("INVALID_PROTOCOL");
    expect(validateTargetValue("file:///etc/passwd").reasonCode).toBe("INVALID_PROTOCOL");
    expect(validateTargetValue("https://user:pass@example.com").reasonCode).toBe("EMBEDDED_CREDENTIALS");
  });
  it("rejects malformed domains, IPs and CIDRs", () => {
    expect(validateTargetValue("not a domain").valid).toBe(false);
    expect(validateTargetValue("999.1.1.1").reasonCode).toBe("INVALID_IP");
    expect(validateTargetValue("10.0.0.0/33").reasonCode).toBe("INVALID_CIDR");
    expect(validateTargetValue("-bad-.com").valid).toBe(false);
  });
  it("blocks localhost, loopback, link-local, metadata and private targets by default", () => {
    for (const bad of ["localhost", "127.0.0.1", "169.254.169.254", "http://169.254.169.254/latest/meta-data/", "metadata.google.internal", "10.1.2.3", "192.168.0.5", "172.16.0.9", "::1"]) {
      expect(validateTargetValue(bad).valid, bad).toBe(false);
      expect(validateTargetValue(bad).reasonCode).toBe("BLOCKED_TARGET");
    }
  });
  it("assertValidTarget throws on malicious input", () => {
    expect(() => assertValidTarget("example.com;id")).toThrow();
    expect(assertValidTarget("example.com")).toBe("example.com");
  });
  it("DNS-rebinding guard re-checks resolved addresses", () => {
    expect(() => assertResolvedAddressesSafe(["93.184.216.34"])).not.toThrow();
    expect(() => assertResolvedAddressesSafe(["93.184.216.34", "169.254.169.254"])).toThrow();
    expect(() => assertResolvedAddressesSafe(["10.0.0.7"])).toThrow();
  });
});
