import { describe, expect, it } from "vitest";
import { assertScanTransition, canTransitionScan, InvalidScanTransitionError } from "./index";

describe("scan state transitions", () => {
  it("allows the happy path QUEUED -> PREPARING -> RUNNING -> COMPLETED", () => {
    expect(canTransitionScan("QUEUED", "PREPARING")).toBe(true);
    expect(canTransitionScan("PREPARING", "RUNNING")).toBe(true);
    expect(canTransitionScan("RUNNING", "COMPLETED")).toBe(true);
  });
  it("allows pause/resume and cancel from active states", () => {
    expect(canTransitionScan("RUNNING", "PAUSED")).toBe(true);
    expect(canTransitionScan("PAUSED", "RUNNING")).toBe(true);
    expect(canTransitionScan("QUEUED", "CANCELLED")).toBe(true);
  });
  it("forbids transitions out of terminal states", () => {
    expect(canTransitionScan("COMPLETED", "RUNNING")).toBe(false);
    expect(canTransitionScan("CANCELLED", "QUEUED")).toBe(false);
    expect(canTransitionScan("FAILED", "RUNNING")).toBe(false);
  });
  it("forbids skipping states", () => {
    expect(canTransitionScan("QUEUED", "COMPLETED")).toBe(false);
    expect(() => assertScanTransition("QUEUED", "COMPLETED")).toThrow(InvalidScanTransitionError);
  });
});
