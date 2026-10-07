import { describe, expect, it } from "vitest";
import { createScopeSchema, createTargetSchema, paginationSchema } from "./index";

describe("target validation", () => {
  it("accepts a matching domain target", () => {
    expect(createTargetSchema.safeParse({ name: "Main", type: "DOMAIN", value: "example.com" }).success).toBe(true);
  });
  it("rejects an IP value for a DOMAIN target", () => {
    expect(createTargetSchema.safeParse({ name: "x", type: "DOMAIN", value: "not a domain" }).success).toBe(false);
  });
  it("validates CIDR and URL targets by type", () => {
    expect(createTargetSchema.safeParse({ name: "n", type: "CIDR", value: "10.0.0.0/24" }).success).toBe(true);
    expect(createTargetSchema.safeParse({ name: "n", type: "CIDR", value: "10.0.0.0/99" }).success).toBe(false);
    expect(createTargetSchema.safeParse({ name: "w", type: "WEB_APPLICATION", value: "https://app.example.com" }).success).toBe(true);
    expect(createTargetSchema.safeParse({ name: "w", type: "WEB_APPLICATION", value: "ftp://x" }).success).toBe(false);
  });
});

describe("scope validation", () => {
  it("accepts structured rules", () => {
    const r = createScopeSchema.safeParse({
      targetId: "123e4567-e89b-12d3-a456-426614174000",
      name: "Prod scope",
      rules: { includeHosts: ["example.com"], allowedPorts: [443], allowedPaths: ["/api"], excludedPaths: ["/admin"] },
    });
    expect(r.success).toBe(true);
  });
  it("rejects out-of-range ports and bad CIDRs", () => {
    const badPort = createScopeSchema.safeParse({
      targetId: "123e4567-e89b-12d3-a456-426614174000", name: "s",
      rules: { allowedPorts: [70000] },
    });
    expect(badPort.success).toBe(false);
    const badCidr = createScopeSchema.safeParse({
      targetId: "123e4567-e89b-12d3-a456-426614174000", name: "s",
      rules: { includeCidrs: ["10.0.0.0/99"] },
    });
    expect(badCidr.success).toBe(false);
  });
});

describe("pagination", () => {
  it("applies defaults and clamps pageSize", () => {
    expect(paginationSchema.parse({}).pageSize).toBe(20);
    expect(paginationSchema.safeParse({ pageSize: 500 }).success).toBe(false);
  });
});
