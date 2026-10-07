import { describe, expect, it } from "vitest";
import { MockSecurityAdapter } from "./mock.adapter";

describe("MockSecurityAdapter", () => {
  it("runs the full lifecycle and returns zero findings, clearly marked mock", async () => {
    const a = new MockSecurityAdapter();
    const target = { type: "DOMAIN" as const, value: "example.com", host: "example.com" };
    await a.validateTarget(target);
    const plan = await a.buildExecutionPlan(target, {});
    expect(plan.networkPolicy).toBe("NO_NETWORK");
    await a.execute(plan);
    const result = await a.normalize(await a.parse(""));
    expect(result.mock).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect((await a.healthCheck()).status).toBe("HEALTHY");
  });
  it("rejects unsupported target types", async () => {
    const a = new MockSecurityAdapter();
    await expect(a.validateTarget({ type: "APK", value: "x", host: "x" })).rejects.toThrow();
  });
});
