import { Inject, Injectable } from "@nestjs/common";
import { createConnection } from "node:net";
import IORedis from "ioredis";
import { loadEnv } from "@dsrclone/config";
import { PRISMA, type PrismaClientLike } from "../prisma/prisma.module";
import type { HealthCheck } from "@dsrclone/types";

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

    const redis = new IORedis(env.REDIS_URL, { lazyConnect: true, maxRetriesPerRequest: 1, connectTimeout: 800 });
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
      const up = await tcpCheck(minioUrl.hostname, Number(minioUrl.port || 9000));
      checks.minio = up ? { status: "ok" } : { status: "down", detail: "object storage unreachable" };
    } catch {
      checks.minio = { status: "down", detail: "object storage misconfigured" };
    }

    try {
      const aiUrl = new URL(env.AI_SERVICE_URL);
      const up = await tcpCheck(aiUrl.hostname, Number(aiUrl.port || 8000));
      checks.ai = up ? { status: "ok" } : { status: "down", detail: "ai service unreachable" };
    } catch {
      checks.ai = { status: "skipped" };
    }

    const down = Object.values(checks).filter((c) => c.status === "down").length;
    return { status: down === 0 ? "ok" : down === Object.keys(checks).length - 1 ? "down" : "degraded", checks };
  }
}
