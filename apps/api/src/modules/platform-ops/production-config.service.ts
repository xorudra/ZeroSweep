import { Injectable } from "@nestjs/common";
import { loadEnv, validateProductionConfig } from "@dsrclone/config";
import { evaluateProductionConfig, type ConfigViolation } from "@dsrclone/security-sdk";

/**
 * ProductionConfigurationService (Prompt 38 §16): the single place the
 * platform validates its own production configuration — at startup
 * (fail fast, §17) and on demand for the admin platform view. Combines
 * the Prompt 25 gate with the V2 grouped rules (secret-reference form,
 * DB connection budget). It reports rule NAMES and groups only; secret
 * values are never returned, logged or stored.
 */
@Injectable()
export class ProductionConfigurationService {
  evaluate(env: NodeJS.ProcessEnv = process.env): {
    mode: string;
    violations: ConfigViolation[];
    legacyViolations: string[];
    ok: boolean;
  } {
    const appEnv = loadEnv();
    const secretRefs: Record<string, string> = {};
    for (const [k, v] of Object.entries(env)) {
      if (k.endsWith("_SECRET_REF") && typeof v === "string") secretRefs[k] = v;
    }
    const violations = evaluateProductionConfig({
      nodeEnv: appEnv.NODE_ENV,
      databaseUrl: env.DATABASE_URL,
      databaseConnectionLimit: appEnv.DATABASE_CONNECTION_LIMIT,
      databaseRequireTls: appEnv.DATABASE_REQUIRE_TLS,
      redisUrl: env.REDIS_URL,
      redisRequireTls: appEnv.REDIS_REQUIRE_TLS,
      jwtSecret: env.JWT_SECRET,
      corsOrigin: appEnv.API_CORS_ORIGIN,
      secretRefs,
      dbConnectionBudget: env.DB_CONNECTION_BUDGET ? Number(env.DB_CONNECTION_BUDGET) : undefined,
      plannedReplicas: env.PLANNED_REPLICAS ? Number(env.PLANNED_REPLICAS) : undefined,
    });
    const legacyViolations = validateProductionConfig(appEnv);
    return {
      mode: appEnv.NODE_ENV,
      violations,
      legacyViolations,
      ok: violations.length === 0 && legacyViolations.length === 0,
    };
  }

  /** Fail-fast boot gate (§17): throws with rule names only. */
  assertBootSafe(env: NodeJS.ProcessEnv = process.env): void {
    const report = this.evaluate(env);
    if (!report.ok) {
      const names = [
        ...report.violations.map((v) => `${v.group}:${v.rule}`),
        ...report.legacyViolations,
      ];
      throw new Error(`Refusing to start — invalid production configuration: ${names.join("; ")}`);
    }
  }
}
