import { describe, expect, it } from "vitest";
import { findingFingerprint } from "./fingerprint";
import { severityFromCvss } from "./severity";

describe("findingFingerprint", () => {
  const parts = { toolFamily: "nuclei", asset: "Example.COM", endpoint: "/Login", parameter: "next", vulnClass: "open-redirect", cwe: "CWE-601" };
  it("is deterministic and case-normalized", () => {
    expect(findingFingerprint(parts)).toBe(findingFingerprint({ ...parts, asset: "example.com", endpoint: "/login" }));
    expect(findingFingerprint(parts)).toMatch(/^[a-f0-9]{64}$/);
  });
  it("changes when the vulnerability class or asset changes", () => {
    expect(findingFingerprint(parts)).not.toBe(findingFingerprint({ ...parts, vulnClass: "xss" }));
    expect(findingFingerprint(parts)).not.toBe(findingFingerprint({ ...parts, asset: "other.com" }));
  });
  it("never invents severity from a missing CVSS score", () => {
    expect(severityFromCvss(undefined)).toBeUndefined();
    expect(severityFromCvss(9.8)).toBe("CRITICAL");
    expect(severityFromCvss(0)).toBe("INFORMATIONAL");
  });
});
