import { Injectable } from "@nestjs/common";
import type { NextFunction, Request, Response } from "express";
import { HealthService } from "./health.service";

/**
 * Minimal Prometheus exposition (Prompt 25 §102–§104): HTTP request counters
 * by method/status class, process gauges, and dependency-up gauges fed by
 * the health service (cached 15s so scrapes cannot stampede dependencies).
 * Labels are bounded (method, status class) — never per-URL or per-tenant,
 * which would explode cardinality and leak tenant structure.
 */
@Injectable()
export class MetricsService {
  private readonly counters = new Map<string, number>();
  private cachedDeps: { at: number; lines: string[] } | null = null;

  constructor(private readonly health: HealthService) {}

  private readonly histogram = new Map<string, number>();
  private static readonly LATENCY_BUCKETS = [0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

  middleware() {
    return (req: Request, res: Response, next: NextFunction): void => {
      const startedAt = process.hrtime.bigint();
      res.on("finish", () => {
        const key = `zerosweep_http_requests_total{method="${req.method}",status_class="${Math.floor(res.statusCode / 100)}xx"}`;
        this.counters.set(key, (this.counters.get(key) ?? 0) + 1);
        // Prompt 38 §99: latency histogram by ROUTE TEMPLATE (the
        // Express route pattern, e.g. /api/v1/scans/:id) — never the
        // raw URL, whose IDs would explode cardinality (§107).
        const route = (req as Request & { route?: { path?: string } }).route?.path ?? "unmatched";
        const seconds = Number(process.hrtime.bigint() - startedAt) / 1e9;
        for (const le of MetricsService.LATENCY_BUCKETS) {
          if (seconds <= le) {
            const k = `zerosweep_http_request_duration_seconds_bucket{route="${route}",le="${le}"}`;
            this.histogram.set(k, (this.histogram.get(k) ?? 0) + 1);
          }
        }
        const inf = `zerosweep_http_request_duration_seconds_bucket{route="${route}",le="+Inf"}`;
        this.histogram.set(inf, (this.histogram.get(inf) ?? 0) + 1);
        const count = `zerosweep_http_request_duration_seconds_count{route="${route}"}`;
        this.histogram.set(count, (this.histogram.get(count) ?? 0) + 1);
      });
      next();
    };
  }

  private async dependencyLines(): Promise<string[]> {
    if (this.cachedDeps && Date.now() - this.cachedDeps.at < 15_000) return this.cachedDeps.lines;
    const { checks } = await this.health.check();
    const lines = Object.entries(checks).map(
      ([name, c]) => `zerosweep_dependency_up{dependency="${name}"} ${c.status === "ok" ? 1 : 0}`,
    );
    this.cachedDeps = { at: Date.now(), lines };
    return lines;
  }

  async render(): Promise<string> {
    const mem = process.memoryUsage();
    const lines: string[] = [
      "# HELP zerosweep_http_requests_total HTTP requests by method and status class.",
      "# TYPE zerosweep_http_requests_total counter",
      ...[...this.counters.entries()].map(([k, v]) => `${k} ${v}`),
      "# HELP zerosweep_process_uptime_seconds Process uptime in seconds.",
      "# TYPE zerosweep_process_uptime_seconds gauge",
      `zerosweep_process_uptime_seconds ${Math.floor(process.uptime())}`,
      "# HELP zerosweep_process_memory_bytes Process memory usage by kind.",
      "# TYPE zerosweep_process_memory_bytes gauge",
      `zerosweep_process_memory_bytes{kind="rss"} ${mem.rss}`,
      `zerosweep_process_memory_bytes{kind="heap_used"} ${mem.heapUsed}`,
      "# HELP zerosweep_http_request_duration_seconds HTTP request latency by route template.",
      "# TYPE zerosweep_http_request_duration_seconds histogram",
      ...[...this.histogram.entries()].map(([k, v]) => `${k} ${v}`),
      "# HELP zerosweep_dependency_up 1 when a checked dependency is reachable.",
      "# TYPE zerosweep_dependency_up gauge",
      ...(await this.dependencyLines()),
    ];
    return lines.join("\n") + "\n";
  }
}
