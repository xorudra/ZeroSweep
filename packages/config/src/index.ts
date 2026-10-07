import { z } from "zod";

/** Shared environment schema. Every service validates its env at boot with this. */
export const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  DATABASE_URL: z.string().min(1).default("postgresql://dsrclone:change-me-local-only@localhost:5432/dsrclone?schema=public"),
  REDIS_URL: z.string().min(1).default("redis://localhost:6379"),
  MINIO_ENDPOINT: z.string().url().default("http://localhost:9000"),
  MINIO_BUCKET: z.string().default("dsrclone-artifacts"),
  AI_SERVICE_URL: z.string().url().default("http://localhost:8000"),
  API_PORT: z.coerce.number().int().positive().default(4000),
  JWT_SECRET: z.string().min(32).default("change-me-local-dev-secret-at-least-32-chars"),
  JWT_EXPIRES_IN: z.string().default("1h"),
  API_CORS_ORIGIN: z.string().default("http://localhost:3000"),
});
export type AppEnv = z.infer<typeof envSchema>;

let cached: AppEnv | undefined;
export function loadEnv(source: NodeJS.ProcessEnv = process.env): AppEnv {
  if (!cached) cached = envSchema.parse(source);
  return cached;
}

export const APP_NAME = "DSRclone";
export const API_PREFIX = "api/v1";
export const QUEUES = {
  ORCHESTRATION: "assessment-orchestration",
  PLACEHOLDER: "dsrclone-placeholder",
  REPORTS: "report-generation",
  NORMALIZATION: "normalization",
} as const;
