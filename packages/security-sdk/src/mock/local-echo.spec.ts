import { describe, expect, it } from "vitest";
import { LocalEchoAdapter } from "./local-echo.adapter";

describe("LocalEchoAdapter", () => {
  it("runs its lifecycle in-process with no findings and mock labelling", async () => {
    const a = new LocalEchoAdapter();
    const target = { type: "DOMAIN" as const, value: "example.com", host: "example.com" };
    await a.validateTarget(target);
    await a.validateConfiguration({ label: "smoke" });
    const plan = await a.buildExecutionPlan(target, { label: "smoke" });
    expect(plan.networkPolicy).toBe("NO_NETWORK");
    expect(plan.arguments).toContain("example.com");
    const exec = await a.execute(plan);
    expect(exec.rawOutputLocation).toContain("memory://");
    const result = await a.normalize(await a.parse(exec.rawOutputLocation ?? ""));
    expect(result.mock).toBe(true);
    expect(result.findings).toHaveLength(0);
  });
  it("rejects raw-command configuration keys", async () => {
    const a = new LocalEchoAdapter();
    await expect(a.validateConfiguration({ command: "id" } as never)).rejects.toThrow(/forbidden/);
    await expect(a.validateConfiguration({ unknownKey: 1 } as never)).rejects.toThrow(/Unknown configuration/);
  });
  it("rejects plan arguments carrying shell metacharacters", async () => {
    const a = new LocalEchoAdapter();
    const target = { type: "DOMAIN" as const, value: "example.com", host: "example.com" };
    const plan = await a.buildExecutionPlan(target, {});
    plan.arguments = ["--target", "example.com; id"];
    await expect(a.execute(plan)).rejects.toThrow(/metacharacters/);
  });
});
