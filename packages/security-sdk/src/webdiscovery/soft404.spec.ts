import { describe, expect, it } from "vitest";
import { Soft404Detector, detectWildcardGroups, responseFingerprint } from "./soft404";
import { SOFT404_BASELINE } from "./fixtures";

describe("soft-404 + fingerprinting + wildcard routes (§17–§19)", () => {
  it("fingerprints are deterministic and length-tolerant for templated pages", () => {
    const a = responseFingerprint({ statusCode: 200, contentLength: 640, wordCount: 42, lineCount: 12, contentType: "text/html; charset=utf-8" });
    const b = responseFingerprint({ statusCode: 200, contentLength: 648, wordCount: 42, lineCount: 12, contentType: "text/html" });
    expect(a).toBe(b); // templated error page echoing a few path bytes
    const real = responseFingerprint({ statusCode: 200, contentLength: 90_210, wordCount: 4000, lineCount: 900, contentType: "application/javascript" });
    expect(real).not.toBe(a);
  });

  it("calibrated detector flags the controlled app's soft-404 twins (§17)", () => {
    const detector = new Soft404Detector([SOFT404_BASELINE]);
    expect(detector.calibrated).toBe(true);
    const twin = detector.classify({ statusCode: 200, contentLength: 640, wordCount: 42, lineCount: 12, contentType: "text/html" });
    expect(twin.isSoft404).toBe(true);
    // A real 404 is never a soft-404, and unrelated pages don't match.
    expect(detector.classify({ statusCode: 404, contentLength: 640, wordCount: 42, lineCount: 12, contentType: "text/html" }).isSoft404).toBe(false);
    expect(detector.classify({ statusCode: 200, contentLength: 512, wordCount: 40, lineCount: 1, contentType: "application/json" }).isSoft404).toBe(false);
    expect(detector.matchesBaseline(responseFingerprint(SOFT404_BASELINE))).toBe(true);
  });

  it("uncalibrated detector never accuses", () => {
    const detector = new Soft404Detector();
    expect(detector.calibrated).toBe(false);
    expect(detector.classify(SOFT404_BASELINE).isSoft404).toBe(false);
  });

  it("wildcard groups collapse identical success shells to one representative (§19)", () => {
    const fp = responseFingerprint({ statusCode: 200, contentLength: 2048, wordCount: 120, lineCount: 30, contentType: "text/html" });
    const items = [
      { url: "https://example.com/app/one", statusCode: 200, fingerprint: fp },
      { url: "https://example.com/app/two", statusCode: 200, fingerprint: fp },
      { url: "https://example.com/app/three", statusCode: 200, fingerprint: fp },
      { url: "https://example.com/admin", statusCode: 200, fingerprint: "different" },
      { url: "https://example.com/gone", statusCode: 404, fingerprint: fp }, // errors never collapse
    ];
    const { kept, groups } = detectWildcardGroups(items);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.behavior).toBe("WILDCARD_ROUTE_BEHAVIOR");
    expect(groups[0]!.collapsed).toHaveLength(2);
    expect(kept.map((k) => k.url)).toContain("https://example.com/admin");
    expect(kept).toHaveLength(3);
  });

  it("two matching paths are not yet a wildcard", () => {
    const fp = "same";
    const { groups } = detectWildcardGroups([
      { url: "https://example.com/a", statusCode: 200, fingerprint: fp },
      { url: "https://example.com/b", statusCode: 200, fingerprint: fp },
    ]);
    expect(groups).toHaveLength(0);
  });
});
