import { Inject, Injectable } from "@nestjs/common";
import { createConnection } from "node:net";
import IORedis from "ioredis";
import { loadEnv } from "@zerosweep/config";
import { PRISMA, type PrismaClientLike } from "../prisma/prisma.module";
import type { HealthCheck } from "@zerosweep/types";

function tcpCheck(host: string, port: number, timeoutMs = 800): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    const done = (ok: boolean) => { socket.destroy(); resolve(ok); };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
  });
}

@Injectable()
export class HealthService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async check(): Promise<HealthCheck> {
    const env = loadEnv();
    const checks: HealthCheck["checks"] = { api: { status: "ok" } };

    try {
      await this.prisma.$queryRaw`SELECT 1`;
      checks.postgres = { status: "ok" };
    } catch {
      checks.postgres = { status: "down", detail: "database unreachable" };
    }

    // Bounded timeouts (connect AND command): a paused-but-connected Redis
    // must fail readiness quickly, never hang the probe (Prompt 25 §89).
    const redis = new IORedis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1, connectTimeout: 800, commandTimeout: 1500 });
    try {
      await redis.connect();
      await redis.ping();
      checks.redis = { status: "ok" };
    } catch {
      checks.redis = { status: "down", detail: "redis unreachable" };
    } finally {
      redis.disconnect();
    }

    try {
      const minioUrl = new URL(env.MINIO_ENDPOINT);
      // Default the probe port by scheme: hosted S3 endpoints are HTTPS
      // URLs whose port the URL parser normalizes away, and probing the
      // MinIO default (9000) for them would report a healthy bucket as
      // down. Non-HTTPS (bare MinIO) endpoints keep the 9000 default.
      const defaultPort = minioUrl.protocol === "https:" ? 443 : 9000;
      const up = await tcpCheck(minioUrl.hostname, Number(minioUrl.port || defaultPort));
      checks.minio = up ? { status: "ok" } : { status: "down", detail: "object storage unreachable" };
    } catch {
      checks.minio = { status: "down", detail: "object storage misconfigured" };
    }

    try {
      const aiUrl = new URL(env.AI_SERVICE_URL);
      const up = await tcpCheck(aiUrl.hostname, Number(aiUrl.port || (aiUrl.protocol === "https:" ? 443 : 8000)));
      checks.ai = up ? { status: "ok" } : { status: "down", detail: "ai service unreachable" };
    } catch {
      checks.ai = { status: "skipped" };
    }

    const down = Object.values(checks).filter((c) => c.status === "down").length;
    return { status: down === 0 ? "ok" : down === Object.keys(checks).length - 1 ? "down" : "degraded", checks };
  }

  /**
   * HTTP-level checks of the peer services (AI copilot, worker, web
   * console) for the platform status view. Unlike the TCP probes in
   * check(), an HTTP response proves the service itself is awake and
   * serving — a sleeping free-tier service only answers after it boots,
   * so a timeout honestly reads as down/"may be waking up", never "ok".
   * Probing also wakes the service, which is the point of the view.
   */
  async serviceChecks(): Promise<HealthCheck["checks"]> {
    const env = loadEnv();
    const probe = async (url: string): Promise<{ status: "ok" | "down"; detail?: string }> => {
      try {
        const res = await fetch(url, { signal: AbortSignal.timeout(4000), redirect: "manual" });
        return res.status >= 200 && res.status < 400
          ? { status: "ok" }
          : { status: "down", detail: `HTTP ${res.status}` };
      } catch {
        return { status: "down", detail: "no response — may be waking up" };
      }
    };
    const [ai, worker, web] = await Promise.all([
      probe(`${env.AI_SERVICE_URL.replace(/\/$/, "")}/health`),
      probe(env.WORKER_SERVICE_URL),
      probe(`${env.WEB_APP_URL.replace(/\/$/, "")}/login`),
    ]);
    return { ai, worker, web };
  }

  /**
   * Liveness (Prompt 25 §86–§88): the process is up and its event loop is
   * responsive. Deliberately performs NO dependency checks.
   */
  live(): { status: "ok"; uptimeSeconds: number } {
    return { status: "ok", uptimeSeconds: Math.floor(process.uptime()) };
  }

  /**
   * Readiness (Prompt 25 §86/§89): required dependencies are PostgreSQL
   * (system of record) and Redis (job queues — without them the API cannot
   * accept scan work). Object storage and the AI service are OPTIONAL: they
   * degrade features, never readiness, and never liveness.
   */
  async ready(): Promise<{
    ready: boolean;
    required: Record<string, { status: string; detail?: string }>;
    optional: Record<string, { status: string; detail?: string }>;
  }> {
    const { checks } = await this.check();
    const required = {
      postgres: checks.postgres ?? { status: "down" },
      redis: checks.redis ?? { status: "down" },
    };
    const optional = {
      minio: checks.minio ?? { status: "skipped" },
      ai: checks.ai ?? { status: "skipped" },
    };
    return { ready: Object.values(required).every((c) => c.status === "ok"), required, optional };
  }
}
