import { z } from "zod";

const booleanFromEnv = z.preprocess(
  (v) => (typeof v === "string" ? ["1", "true", "yes", "on"].includes(v.toLowerCase()) : v),
  z.boolean(),
);

/** Shared environment schema. Every service validates its env at boot with this. */
export const envSchema = z.object({
  // Environment modes (Prompt 25 §32): development | test | staging | production.
  NODE_ENV: z.enum(["development", "test", "staging", "production"]).default("development"),
  DATABASE_URL: z.string().min(1).default("postgresql://dsrclone:change-me-local-only@localhost:5432/dsrclone?schema=public"),
  // Bounded per-instance connection pool (Prompt 25 §35) and DB TLS policy (§34).
  DATABASE_CONNECTION_LIMIT: z.coerce.number().int().min(1).max(100).default(10),
  DATABASE_REQUIRE_TLS: booleanFromEnv.default(false),
  REDIS_URL: z.string().min(1).default("redis://localhost:6379"),
  // Redis TLS/auth travel inside REDIS_URL (rediss:// with credentials); this
  // flag lets a deployment assert TLS is actually in use (Prompt 25 §40).
  REDIS_REQUIRE_TLS: booleanFromEnv.default(false),
  MINIO_ENDPOINT: z.string().url().default("http://localhost:9000"),
  MINIO_BUCKET: z.string().default("dsrclone-artifacts"),
  AI_SERVICE_URL: z.string().url().default("http://localhost:8000"),
  // Peer service URLs for the platform status view (Admin Panel). The
  // defaults are the reference deployment's public URLs; a self-hosted
  // deployment overrides them with its own.
  WORKER_SERVICE_URL: z.string().url().default("https://dsrclone-worker.onrender.com"),
  WEB_APP_URL: z.string().url().default("https://dsrclone-web.onrender.com"),
  API_PORT: z.coerce.number().int().positive().default(4000),
  JWT_SECRET: z.string().min(32).default("change-me-local-dev-secret-at-least-32-chars"),
  JWT_EXPIRES_IN: z.string().default("1h"),
  API_CORS_ORIGIN: z.string().default("http://localhost:3000"),
  // Standalone scheduler process (Prompt 25 §52; lease pattern from Prompt 22).
  SCHEDULER_TICK_MS: z.coerce.number().int().min(1000).max(300000).default(15000),
  SCHEDULER_OWNER_ID: z.string().max(120).optional(),
  // Bearer token for the Prometheus /metrics endpoint. Unset = the
  // endpoint answers 404: scrape surfaces are never left open on a
  // public deployment by default.
  METRICS_TOKEN: z.string().min(16).optional(),
  // Release identity stamped into logs and release manifests (§144–146).
  // Prompt 39 §302/§303: the RC version was the build identity through RC1;
  // Prompt 40 promotes the default to the v1.0 release identity.
  // Deployments may override it via env for hotfix trains.
  RELEASE_VERSION: z.string().max(64).default("1.0.0"),
  GIT_COMMIT: z.string().max(64).optional(),
  // ---- Productization (Prompt 40) -------------------------------------------
  // Product mode comes ONLY from trusted deployment configuration (§4): no
  // tenant-facing API can change it. One codebase serves every mode (§5).
  PRODUCT_MODE: z.enum(["COMMUNITY", "SELF_HOSTED", "SAAS", "ENTERPRISE"]).default("SELF_HOSTED"),
  // Billing provider selection (§19–§21). Unset = billing NOT CONFIGURED:
  // the platform never simulates a successful real payment. "test" is a
  // development/test provider and is refused in production (§21).
  PRODUCT_BILLING_PROVIDER: z.enum(["manual", "test"]).optional(),
  // HMAC secret for billing webhook signature verification (§23). A secret
  // REFERENCE is resolved by the deployment secret store; the raw value is
  // never persisted in the database or returned by any API.
  PRODUCT_BILLING_WEBHOOK_SECRET: z.string().min(16).optional(),
  // Ed25519 public key (PEM) used to verify self-hosted product licenses
  // (§30/§31). The private signing key NEVER ships with the product (§248).
  PRODUCT_LICENSE_PUBLIC_KEY: z.string().optional(),
  // License grace period in days after expiry (§34); 0 disables grace.
  PRODUCT_LICENSE_GRACE_DAYS: z.coerce.number().int().min(0).max(365).default(14),
  // Default trial length for SaaS signups (§54–§57).
  PRODUCT_TRIAL_DAYS: z.coerce.number().int().min(1).max(90).default(14),
  // Platform-admin bootstrap (§96/§98): emails listed here (deployment
  // configuration, comma-separated) are granted the platform-admin flag at
  // signup/registration time. Tenant users cannot self-grant this (§140).
  PRODUCT_PLATFORM_ADMIN_EMAILS: z.string().optional(),
  // Telemetry (§144/§145): OFF by default, documented and configurable.
  // There is no hidden phone-home from self-hosted deployments (§37).
  PRODUCT_TELEMETRY_ENABLED: booleanFromEnv.default(false),
  // Product update checks (§187): disabled unless explicitly enabled by the
  // operator; metadata only, never auto-executes anything (§189).
  PRODUCT_UPDATE_CHECKS_ENABLED: booleanFromEnv.default(false),
});
export type AppEnv = z.infer<typeof envSchema>;

/** Prompt 40 §96: platform-admin bootstrap list from deployment config. */
export function isPlatformAdminEmail(email: string, env: AppEnv): boolean {
  const list = (env.PRODUCT_PLATFORM_ADMIN_EMAILS ?? "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);
  return list.includes(email.trim().toLowerCase());
}

let cached: AppEnv | undefined;
export function loadEnv(source: NodeJS.ProcessEnv = process.env): AppEnv {
  if (!cached) cached = envSchema.parse(source);
  return cached;
}

/**
 * Production configuration gate (Prompt 25 §30/§33): in production mode the
 * platform REFUSES to boot with placeholder secrets, wildcard CORS, unbound
 * pools, or a disabled TLS requirement that the URL does not satisfy.
 * Development/test keep permissive local defaults; staging runs the same
 * checks as warnings-free errors too when explicitly promoted (callers pass
 * `strict`). Returns the list of violations (empty = safe to boot).
 */
export function validateProductionConfig(env: AppEnv): string[] {
  if (env.NODE_ENV !== "production" && env.NODE_ENV !== "staging") return [];
  const violations: string[] = [];
  const PLACEHOLDER = /change-me|replace-(with|from)|example\.com\/|placeholder/i;
  if (PLACEHOLDER.test(env.JWT_SECRET)) violations.push("JWT_SECRET is still a placeholder value");
  if (env.JWT_SECRET.length < 32) violations.push("JWT_SECRET must be at least 32 characters in production");
  if (PLACEHOLDER.test(env.DATABASE_URL)) violations.push("DATABASE_URL still contains a placeholder value");
  if (env.DATABASE_REQUIRE_TLS && !/sslmode=(require|verify-ca|verify-full)/.test(env.DATABASE_URL)) {
    violations.push("DATABASE_REQUIRE_TLS is set but DATABASE_URL lacks sslmode=require/verify-full");
  }
  if (env.REDIS_REQUIRE_TLS && !env.REDIS_URL.startsWith("rediss://")) {
    violations.push("REDIS_REQUIRE_TLS is set but REDIS_URL does not use rediss://");
  }
  if (env.API_CORS_ORIGIN.trim() === "*") violations.push("API_CORS_ORIGIN must not be a wildcard in production");
  if (env.DATABASE_CONNECTION_LIMIT > 50) violations.push("DATABASE_CONNECTION_LIMIT exceeds the per-instance bound of 50");
  return violations;
}

/** Fail-fast startup check: throws (crashing the boot) when a production-like
 *  environment has configuration violations. Never logs secret values. */
export function assertProductionConfig(env: AppEnv): void {
  const violations = validateProductionConfig(env);
  if (violations.length > 0) {
    throw new Error(
      `Refusing to start in ${env.NODE_ENV} mode — invalid production configuration: ${violations.join("; ")}`,
    );
  }
}

export const APP_NAME = "DSRclone";
export const API_PREFIX = "api/v1";
export const QUEUES = {
  ORCHESTRATION: "assessment-orchestration",
  PLACEHOLDER: "dsrclone-placeholder",
  REPORTS: "report-generation",
  NORMALIZATION: "normalization",
  // Prompt 4 §13 orchestration queues. Jobs carry IDs/references only —
  // workers load trusted state from the database, never from payloads.
  SCAN_ORCHESTRATION: "scan-orchestration",
  STAGE_EXECUTION: "stage-execution",
  TOOL_EXECUTION: "tool-execution",
  RESULT_PROCESSING: "result-processing",
  CORRELATION: "correlation",
  RISK_ANALYSIS: "risk-analysis",
  // Prompt 11 §55: targeted vulnerability retests (IDs only payloads).
  RETEST_EXECUTION: "retest-execution",
  // Prompt 16 §12: controlled validation sessions (IDs only payloads).
  VALIDATION_EXECUTION: "validation-execution",
  // Prompt 24 §79: integration outbox draining (IDs only payloads).
  INTEGRATION_OUTBOX: "integration-outbox",
} as const;
