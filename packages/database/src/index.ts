import { PrismaClient } from "@prisma/client";

/**
 * Datasource URL with a BOUNDED connection pool (Prompt 25 §35): when
 * DATABASE_CONNECTION_LIMIT is set it is appended as Prisma's
 * `connection_limit` so a horizontally scaled deployment cannot exhaust the
 * database with unbounded per-instance pools. Unset = driver default.
 */
export function boundedDatasourceUrl(raw: string | undefined, limitRaw: string | undefined): string | undefined {
  if (!raw) return raw;
  const limit = Number(limitRaw);
  if (!limitRaw || !Number.isInteger(limit) || limit < 1 || limit > 100) return raw;
  if (/[?&]connection_limit=/.test(raw)) return raw;
  return `${raw}${raw.includes("?") ? "&" : "?"}connection_limit=${limit}`;
}

/** Single reusable Prisma client (global-cached to survive dev hot reloads). */
const globalForPrisma = globalThis as unknown as { zerosweepPrisma?: PrismaClient };

const datasourceUrl = boundedDatasourceUrl(process.env.DATABASE_URL, process.env.DATABASE_CONNECTION_LIMIT);
export const prisma: PrismaClient =
  globalForPrisma.zerosweepPrisma ??
  new PrismaClient({
    ...(datasourceUrl ? { datasources: { db: { url: datasourceUrl } } } : {}),
    log: process.env.NODE_ENV === "development" ? ["warn", "error"] : ["error"],
  });

if (process.env.NODE_ENV !== "production") globalForPrisma.zerosweepPrisma = prisma;

export * from "@prisma/client";
