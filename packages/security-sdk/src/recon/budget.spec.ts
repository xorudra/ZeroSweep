import { describe, expect, it } from "vitest";
import { ADMIN_DISCOVERY_CAPS, BudgetTracker, clampDiscoveryBudget, DEFAULT_DISCOVERY_BUDGET } from "./budget";

describe("discovery budget (§27–§28)", () => {
  it("defaults are conservative and requests never exceed admin caps", () => {
    expect(clampDiscoveryBudget()).toEqual(DEFAULT_DISCOVERY_BUDGET);
    const clamped = clampDiscoveryBudget({ maxSubdomains: 10_000_000, maxCrawlUrls: 10 });
    expect(clamped.maxSubdomains).toBe(ADMIN_DISCOVERY_CAPS.maxSubdomains);
    expect(clamped.maxCrawlUrls).toBe(10); // lower requests are honoured
  });
  it("tracker consumes until the ceiling, then refuses without consuming", () => {
    const tracker = new BudgetTracker(clampDiscoveryBudget({ maxSubdomains: 2 }));
    expect(tracker.tryConsume("subdomains")).toBe(true);
    expect(tracker.tryConsume("subdomains")).toBe(true);
    expect(tracker.tryConsume("subdomains")).toBe(false);
    expect(tracker.remaining("subdomains")).toBe(0);
    expect(tracker.snapshot().subdomains).toBe(2);
  });
  it("duration ceiling blocks further consumption", () => {
    let now = 1_000_000;
    const tracker = new BudgetTracker(clampDiscoveryBudget({ maxDurationSeconds: 60 }), () => now);
    expect(tracker.tryConsume("requests")).toBe(true);
    now += 61_000;
    expect(tracker.durationExceeded()).toBe(true);
    expect(tracker.tryConsume("requests")).toBe(false);
  });
});
