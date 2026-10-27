import { describe, expect, it } from "vitest";
import { shouldSkipNoInputStage } from "./dag-runner";

describe("shouldSkipNoInputStage (honest pipeline stages)", () => {
  it("skips finding-pipeline stages when tools ran but produced nothing", () => {
    for (const stage of ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS"]) {
      expect(shouldSkipNoInputStage(stage, 2, false)).toBe(true);
    }
  });

  it("runs them when at least one tool produced output", () => {
    for (const stage of ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS"]) {
      expect(shouldSkipNoInputStage(stage, 2, true)).toBe(false);
    }
  });

  it("does not skip before any tool stage has run (pure-platform scans unaffected)", () => {
    for (const stage of ["NORMALIZATION", "CORRELATION", "RISK_ANALYSIS"]) {
      expect(shouldSkipNoInputStage(stage, 0, false)).toBe(false);
    }
  });

  it("never skips the report stage or gate stages", () => {
    for (const stage of ["REPORT_GENERATION", "AUTHORIZATION_CHECK", "SCOPE_VALIDATION", "PASSIVE_RECON"]) {
      expect(shouldSkipNoInputStage(stage, 2, false)).toBe(false);
    }
  });
});
