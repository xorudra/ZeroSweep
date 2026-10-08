import { envSchema, validateProductionConfig, assertProductionConfig } from "@dsrclone/config";

/**
 * Production configuration gate (Prompt 25 §30/§33): placeholder secrets and
 * unsafe production settings must REFUSE the boot; development stays easy.
 */
describe("production config validation", () => {
  const strongDb = "postgresql://dsrclone:supplied-by-secret-store@db.internal:5432/dsrclone?schema=public&sslmode=require";

  it("accepts development defaults without violations", () => {
    const env = envSchema.parse({});
    expect(validateProductionConfig(env)).toEqual([]);
  });

  it("rejects placeholder JWT secret in production", () => {
    const env = envSchema.parse({ NODE_ENV: "production", DATABASE_URL: strongDb });
    const violations = validateProductionConfig(env);
    expect(violations.some((v) => v.includes("JWT_SECRET"))).toBe(true);
    expect(() => assertProductionConfig(env)).toThrow(/Refusing to start/);
  });

  it("rejects placeholder database password in production", () => {
    const env = envSchema.parse({
      NODE_ENV: "production",
      JWT_SECRET: "a-very-strong-production-secret-value-0123456789",
    });
    expect(validateProductionConfig(env).some((v) => v.includes("DATABASE_URL"))).toBe(true);
  });

  it("rejects wildcard CORS and demands TLS when required", () => {
    const env = envSchema.parse({
      NODE_ENV: "production",
      JWT_SECRET: "a-very-strong-production-secret-value-0123456789",
      DATABASE_URL: "postgresql://dsrclone:pw@db.internal:5432/dsrclone",
      DATABASE_REQUIRE_TLS: "true",
      REDIS_URL: "redis://redis.internal:6379",
      REDIS_REQUIRE_TLS: "true",
      API_CORS_ORIGIN: "*",
    });
    const violations = validateProductionConfig(env);
    expect(violations.some((v) => v.includes("DATABASE_REQUIRE_TLS"))).toBe(true);
    expect(violations.some((v) => v.includes("REDIS_REQUIRE_TLS"))).toBe(true);
    expect(violations.some((v) => v.includes("API_CORS_ORIGIN"))).toBe(true);
  });

  it("passes a fully supplied production environment", () => {
    const env = envSchema.parse({
      NODE_ENV: "production",
      JWT_SECRET: "a-very-strong-production-secret-value-0123456789",
      DATABASE_URL: strongDb,
      DATABASE_REQUIRE_TLS: "true",
      REDIS_URL: "rediss://:pw@redis.internal:6379",
      REDIS_REQUIRE_TLS: "true",
      API_CORS_ORIGIN: "https://app.example.com",
    });
    expect(validateProductionConfig(env)).toEqual([]);
    expect(() => assertProductionConfig(env)).not.toThrow();
  });

  it("supports the staging environment mode (§32)", () => {
    const env = envSchema.parse({ NODE_ENV: "staging", DATABASE_URL: strongDb });
    expect(env.NODE_ENV).toBe("staging");
    expect(validateProductionConfig(env).some((v) => v.includes("JWT_SECRET"))).toBe(true);
  });
});
