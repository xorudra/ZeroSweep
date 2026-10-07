import { describe, expect, it } from "vitest";
import { ToolRegistry } from "./registry";
import { MockSecurityAdapter } from "../mock/mock.adapter";
import { LocalEchoAdapter } from "../mock/local-echo.adapter";
import type { ToolMetadata } from "../adapter/adapter.types";
import { BaseSecurityToolAdapter } from "../adapter/adapter.base";

class FakeAdapter extends BaseSecurityToolAdapter {
  constructor(readonly metadata: ToolMetadata) { super(); }
  async buildExecutionPlan(): Promise<never> { throw new Error("not implemented"); }
  async execute(): Promise<never> { throw new Error("not implemented"); }
  async parse(): Promise<unknown> { return {}; }
  async normalize(): Promise<never> { throw new Error("not implemented"); }
}

const meta = (over: Partial<ToolMetadata>): ToolMetadata => ({
  id: "x", slug: "x-tool", name: "X", description: "d", category: "WEB", adapterVersion: "1.0.0",
  licenseType: "OPEN_SOURCE", executionMode: "CONTAINER", riskLevel: "LOW",
  supportedTargetTypes: ["WEB_APPLICATION"], supportedOutputFormats: ["JSON"],
  capabilities: ["VULNERABILITY_SCANNING"], requiresCredentials: [], requiresApproval: false,
  supportsContainerExecution: true, supportsCancellation: true, supportsProgress: false,
  defaultTimeoutSeconds: 60, maxTimeoutSeconds: 600, resources: { cpu: "1", memory: "512Mi", timeoutSeconds: 60 },
  ...over,
});

describe("ToolRegistry", () => {
  it("registers and resolves by slug, id, category, capability and target type", () => {
    const r = new ToolRegistry();
    r.register(new MockSecurityAdapter());
    r.register(new LocalEchoAdapter());
    expect(r.resolve("mock")).toBeDefined();
    expect(r.resolveById("local-echo")).toBeDefined();
    expect(r.byCategory("REPORTING")).toHaveLength(2);
    expect(r.byTargetType("DOMAIN")).toHaveLength(2);
    expect(r.byTargetType("APK")).toHaveLength(0);
    expect(r.isCompatible("mock", "DOMAIN")).toBe(true);
    expect(r.isCompatible("mock", "APK")).toBe(false);
    expect(r.query({ targetType: "WEB_APPLICATION" })).toHaveLength(2);
  });
  it("resolves by capability", () => {
    const r = new ToolRegistry();
    r.register(new FakeAdapter(meta({})));
    expect(r.byCapability("VULNERABILITY_SCANNING")).toHaveLength(1);
    expect(r.byCapability("SAST")).toHaveLength(0);
  });
  it("rejects duplicate slug and duplicate id", () => {
    const r = new ToolRegistry();
    r.register(new MockSecurityAdapter());
    expect(() => r.register(new MockSecurityAdapter())).toThrow(/Duplicate/);
    const r2 = new ToolRegistry();
    r2.register(new FakeAdapter(meta({})));
    expect(() => r2.register(new FakeAdapter(meta({ slug: "other-tool" })))).toThrow(/Duplicate adapter id/);
  });
  it("rejects invalid metadata at registration", () => {
    const r = new ToolRegistry();
    expect(() => r.register(new FakeAdapter(meta({ slug: "Bad Slug!" })))).toThrow();
    expect(() => r.register(new FakeAdapter(meta({ defaultTimeoutSeconds: 0 })))).toThrow();
    expect(() => r.register(new FakeAdapter(meta({ maxTimeoutSeconds: 1 }))) ).toThrow();
    expect(() => r.register(new FakeAdapter(meta({ riskLevel: "RESTRICTED", requiresApproval: false })))).toThrow();
    expect(() => r.register(new FakeAdapter(meta({ inputSchema: [{ name: "command", type: "string" }] })))).toThrow(/forbidden/);
  });
  it("unregisters cleanly", () => {
    const r = new ToolRegistry();
    r.register(new MockSecurityAdapter());
    expect(r.unregister("mock")).toBe(true);
    expect(r.resolve("mock")).toBeUndefined();
    expect(r.unregister("mock")).toBe(false);
  });
});
