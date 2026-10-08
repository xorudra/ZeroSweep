/**
 * Production configuration V2 (Prompt 38 §16–§28): grouped validation on
 * top of the Prompt 25 production gate. The API's
 * ProductionConfigurationService evaluates the process environment with
 * these pure functions at startup (fail fast, §17) and for the admin
 * platform view. Secret VALUES are never returned — only which rule
 * failed, so reports are safe to store and display.
 */

export const CONFIG_GROUPS = [
  "application",
  "database",
  "redis",
  "queues",
  "objectStorage",
  "identity",
  "email",
  "ai",
  "scannerInfrastructure",
  "integrations",
  "observability",
  "security",
] as const;
export type ConfigGroup = (typeof CONFIG_GROUPS)[number];

export interface ConfigViolation {
  group: ConfigGroup;
  rule: string;
  message: string;
}

const PLACEHOLDER = /change-me|replace-(with|from)|placeholder|example\.com/i;

/**
 * Secret references (§21–§24): production secrets are REFERENCES, never
 * inline values. Accepted forms: `env:NAME`, `file:/abs/path`,
 * `docker-secret:name`, `k8s-secret:namespace/name/key`,
 * `vault:path#key`, `aws-sm:secret-id`, `gcp-sm:projects/p/secrets/s`,
 * `azure-kv:vault/secret`. A bare value in a *_REF variable is a
 * plaintext secret and is refused.
 */
const SECRET_REF = /^(env:[A-Z][A-Z0-9_]*|file:\/[^\s]+|docker-secret:[a-z0-9._-]+|k8s-secret:[a-z0-9.-]+\/[a-z0-9._-]+\/[a-z0-9._-]+|vault:[^\s#]+#[A-Za-z0-9._-]+|aws-sm:[A-Za-z0-9/_+=.@-]+|gcp-sm:projects\/[a-z0-9-]+\/secrets\/[A-Za-z0-9_-]+|azure-kv:[a-z0-9-]+\/[A-Za-z0-9-]+)$/;

export function isSecretReference(value: string): boolean {
  return SECRET_REF.test(value.trim());
}

export interface ProductionConfigInput {
  nodeEnv: string;
  databaseUrl?: string;
  databaseConnectionLimit?: number;
  databaseRequireTls?: boolean;
  redisUrl?: string;
  redisRequireTls?: boolean;
  jwtSecret?: string;
  corsOrigin?: string;
  /** Every environment variable whose name ends in `_SECRET_REF`. */
  secretRefs?: Record<string, string>;
  /** Total platform DB connection budget for the deployment (§27). */
  dbConnectionBudget?: number;
  /** Planned API + worker + scheduler replicas sharing the budget. */
  plannedReplicas?: number;
}

/** Grouped production violations. Empty array = safe to boot (§17). */
export function evaluateProductionConfig(input: ProductionConfigInput): ConfigViolation[] {
  const out: ConfigViolation[] = [];
  const prod = input.nodeEnv === "production" || input.nodeEnv === "staging";
  if (!prod) return out;
  const v = (group: ConfigGroup, rule: string, message: string) => out.push({ group, rule, message });

  if (!input.databaseUrl) v("database", "DB_URL_REQUIRED", "DATABASE_URL is required in production");
  else if (PLACEHOLDER.test(input.databaseUrl)) v("database", "DB_URL_PLACEHOLDER", "DATABASE_URL still contains a placeholder value");
  if (input.databaseRequireTls && input.databaseUrl && !/sslmode=(require|verify-ca|verify-full)/.test(input.databaseUrl)) {
    v("database", "DB_TLS", "DATABASE_REQUIRE_TLS is set but DATABASE_URL lacks sslmode=require/verify-*");
  }
  if (input.redisRequireTls && input.redisUrl && !input.redisUrl.startsWith("rediss://")) {
    v("redis", "REDIS_TLS", "REDIS_REQUIRE_TLS is set but REDIS_URL does not use rediss://");
  }
  if (!input.jwtSecret || PLACEHOLDER.test(input.jwtSecret)) {
    v("security", "JWT_PLACEHOLDER", "JWT_SECRET is missing or still a placeholder value");
  } else if (input.jwtSecret.length < 32) {
    v("security", "JWT_LENGTH", "JWT_SECRET must be at least 32 characters in production");
  }
  if (input.corsOrigin?.trim() === "*") v("application", "CORS_WILDCARD", "API_CORS_ORIGIN must not be a wildcard in production");
  for (const [name, value] of Object.entries(input.secretRefs ?? {})) {
    if (!isSecretReference(value)) {
      v("security", "SECRET_REF_FORM", `${name} is not a recognised secret reference (env:/file:/docker-secret:/k8s-secret:/vault:/aws-sm:/gcp-sm:/azure-kv:) — plaintext secrets are refused`);
    }
  }
  const budget = connectionBudget({
    connectionLimitPerReplica: input.databaseConnectionLimit ?? 10,
    replicas: input.plannedReplicas ?? 1,
    budget: input.dbConnectionBudget,
  });
  if (!budget.withinBudget) {
    v("database", "DB_CONNECTION_BUDGET", `planned connections ${budget.planned} exceed the database connection budget ${budget.budget} (§27)`);
  }
  return out;
}

/**
 * DB connection budget (§26–§28): every replica holds its own Prisma
 * pool, so the deployment plan must multiply before it scales.
 * `headroom` reserves connections for migrations, admin and the
 * provider's own overhead.
 */
export function connectionBudget(input: {
  connectionLimitPerReplica: number;
  replicas: number;
  budget?: number;
  headroom?: number;
}): { planned: number; budget: number; withinBudget: boolean } {
  const budget = input.budget ?? 100;
  const headroom = input.headroom ?? 10;
  const planned = input.connectionLimitPerReplica * Math.max(1, input.replicas) + headroom;
  return { planned, budget, withinBudget: planned <= budget };
}

/** Redis durability classes (§38): queue state is reconstructable from
 *  Postgres (jobs are re-dispatchable by ID); only rate-limit/lock state
 *  is truly ephemeral. Nothing durability-sensitive may live ONLY in
 *  Redis — that is why Redis backup is optional (§162). */
export const REDIS_DURABILITY_CLASSES = {
  cache: "ephemeral",
  rateLimits: "ephemeral",
  locks: "ephemeral",
  queues: "reconstructable",
  schedulerLeases: "reconstructable",
} as const;
