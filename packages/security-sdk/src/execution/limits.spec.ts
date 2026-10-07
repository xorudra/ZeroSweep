import { describe, expect, it } from "vitest";
import { clampRateLimits, clampTimeout, enforceOutputLimits, truncateSafely } from "./limits";
import { defaultContainerSpec } from "./execution.types";

describe("execution limits (Prompt 3 §30-§33)", () => {
  it("clamps timeouts to adapter and admin maximums", () => {
    expect(clampTimeout(60, 600)).toBe(60);
    expect(() => clampTimeout(7200, 99999)).toThrow(/exceeds maximum/);
    expect(() => clampTimeout(700, 600)).toThrow();
    expect(() => clampTimeout(0, 600)).toThrow();
  });
  it("clamps rate limits to admin ceilings", () => {
    const r = clampRateLimits({ requestsPerMinute: 100000, maxConcurrency: 99 });
    expect(r.requestsPerMinute).toBeLessThanOrEqual(60);
    expect(r.maxConcurrency).toBeLessThanOrEqual(2);
  });
  it("enforces output limits", () => {
    expect(() => enforceOutputLimits({ stdoutBytes: 10, stderrBytes: 10, artifactSizes: [100] })).not.toThrow();
    expect(() => enforceOutputLimits({ stdoutBytes: 11 * 1024 * 1024, stderrBytes: 0, artifactSizes: [] })).toThrow(/stdout/);
    expect(() => enforceOutputLimits({ stdoutBytes: 0, stderrBytes: 0, artifactSizes: Array(51).fill(1) })).toThrow(/count/);
  });
  it("truncates safely and reports it", () => {
    expect(truncateSafely("abc", 10)).toEqual({ text: "abc", truncated: false });
    expect(truncateSafely("abcdef", 3).truncated).toBe(true);
  });
  it("container spec defaults are the secure posture", () => {
    const s = defaultContainerSpec({ image: "img:1", args: [] });
    expect(s.runAsNonRoot).toBe(true);
    expect(s.readOnlyRootFilesystem).toBe(true);
    expect(s.privileged).toBe(false);
    expect(s.dropCapabilities).toEqual(["ALL"]);
    expect(s.networkMode).toBe("SCOPE_ONLY");
  });
});
