import { describe, expect, it } from "vitest";
import { redact, REDACTED } from "./index";

describe("logger redaction", () => {
  it("redacts sensitive keys at any depth", () => {
    const out = redact({ user: "a", password: "x", nested: { api_key: "y", ok: 1 }, authorization: "Bearer z" }) as Record<string, unknown>;
    expect(out.password).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).api_key).toBe(REDACTED);
    expect((out.nested as Record<string, unknown>).ok).toBe(1);
    expect(out.authorization).toBe(REDACTED);
  });
  it("passes primitives through untouched", () => {
    expect(redact(42)).toBe(42);
    expect(redact("plain")).toBe("plain");
  });
});
